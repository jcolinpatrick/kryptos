#!/usr/bin/env python3
# Cipher: columnar transposition
# Family: grille
# Status: active
# Keyspace: widths 4-14, all perms for <=9, keyword-based for 10-14
# Last run:
# Best score:
#
# Statistical Transposition Detector for Kryptos K4.
#
# Goal: Identify the correct columnar transposition (if one exists)
# INDEPENDENTLY of the substitution cipher, using only statistical properties
# of the text.
#
# Rationale:
# - IC is transposition-invariant (letter frequencies don't change).
# - But DIGRAM frequencies, trigram repeats, and long repeated substrings
#   DO change. Correct untransposition restores the substitution's original
#   structure, which has characteristic patterns:
#   - Periodic substitution creates periodic key -> repeated digrams/trigrams
#     at period intervals.
#   - Any substitution maps English digrams to CT digrams, so the CT digram
#     distribution should be closer to a substitution-of-English distribution
#     than a transposition-of-that distribution.
# - Chi-squared distance of letter-pair contacts from English is a proxy for
#   structural ordering.
#
# Statistics computed:
#   1. Digram IC (probability two adjacent pairs match) - should increase
#   2. Repeated bigram count - should increase
#   3. Repeated trigram count - should increase
#   4. Longest repeated substring - should increase
#   5. Chi-squared of bigram frequencies vs uniform - more peaked = more structured
#   6. Serial correlation of letter indices - measures ordering structure
#   7. Even-odd IC difference - for period-2 structure detection
#
# Usage: PYTHONPATH=src python3 -u scripts/grille/e_transposition_detector.py

from __future__ import annotations

import math
import sys
import time
import json
from collections import Counter, defaultdict
from itertools import permutations
from typing import List, Tuple, Dict, Optional

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX

# ── English reference frequencies ────────────────────────────────────────────

ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253,
    'E': 0.12702, 'F': 0.02228, 'G': 0.02015, 'H': 0.06094,
    'I': 0.06966, 'J': 0.00153, 'K': 0.00772, 'L': 0.04025,
    'M': 0.02406, 'N': 0.06749, 'O': 0.07507, 'P': 0.01929,
    'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150,
    'Y': 0.01974, 'Z': 0.00074,
}

# English bigram frequencies (top 30 for chi-squared comparison)
ENGLISH_BIGRAMS_TOP = {
    'TH': 0.0356, 'HE': 0.0307, 'IN': 0.0243, 'ER': 0.0205,
    'AN': 0.0199, 'RE': 0.0185, 'ON': 0.0176, 'AT': 0.0149,
    'EN': 0.0145, 'ND': 0.0135, 'TI': 0.0134, 'ES': 0.0134,
    'OR': 0.0128, 'TE': 0.0120, 'OF': 0.0117, 'ED': 0.0117,
    'IS': 0.0113, 'IT': 0.0112, 'AL': 0.0109, 'AR': 0.0107,
    'ST': 0.0105, 'TO': 0.0104, 'NT': 0.0104, 'NG': 0.0095,
    'SE': 0.0093, 'HA': 0.0093, 'AS': 0.0087, 'OU': 0.0087,
    'IO': 0.0083, 'LE': 0.0083,
}

# Thematic keywords for width 10-14
THEMATIC_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "ENIGMA", "COMPASS", "KOMPASS", "DEFECTOR",
    "COLOPHON", "BERLIN", "CLOCK", "FIVE", "POINT", "LUCID",
    "MEMORY", "FORCES", "DIGITAL", "INVISIBLE", "POSITION",
    "MATRIX", "CIPHER", "SECRET", "QUAGMIRE", "VERDIGRIS",
    "GNOMON", "OCULUS", "TRIPTYCH", "ARMATURE", "DOLMEN",
    "FILIGREE", "PARALLAX", "REVETEMENT", "CENOTAPH", "OUBLIETTE",
    "ESCUTCHEON",
]


# ── Columnar transposition ───────────────────────────────────────────────────

def columnar_decrypt(ct: str, col_order: List[int]) -> str:
    """Reverse columnar transposition given column read order.

    Encryption: write PT into rows of width=ncols, read columns in col_order.
    Decryption: distribute CT chars back into columns in col_order, read rows.
    """
    ncols = len(col_order)
    nrows = math.ceil(len(ct) / ncols)
    total = nrows * ncols
    short_cols = total - len(ct)

    # Determine how many chars each column gets
    # Last 'short_cols' columns (in natural order) are short
    col_lengths = []
    for col_natural in range(ncols):
        if col_natural >= ncols - short_cols:
            col_lengths.append(nrows - 1)
        else:
            col_lengths.append(nrows)

    # Distribute CT into columns in the given order
    grid = [[] for _ in range(ncols)]
    pos = 0
    for order_idx in range(ncols):
        col_idx = col_order[order_idx]
        length = col_lengths[col_idx]
        grid[col_idx] = list(ct[pos:pos + length])
        pos += length

    # Read rows
    result = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(grid[col]):
                result.append(grid[col][row])
    return "".join(result)


def keyword_to_col_order(keyword: str, width: int) -> List[int]:
    """Convert a keyword to a column ordering for columnar transposition.

    The keyword is truncated or extended to match width.
    Column order = the order in which columns are read during encryption,
    determined by alphabetical rank of keyword letters.
    """
    if len(keyword) < width:
        # Extend by cycling
        keyword = (keyword * ((width // len(keyword)) + 1))[:width]
    else:
        keyword = keyword[:width]

    # Rank letters alphabetically (stable sort for ties)
    indexed = sorted(range(width), key=lambda i: (keyword[i], i))
    # indexed[rank] = original_col → this gives the read order
    return indexed


# ── Statistical measures ─────────────────────────────────────────────────────

def ic(text: str) -> float:
    """Index of Coincidence."""
    freq = Counter(text)
    n = len(text)
    if n <= 1:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def digram_ic(text: str) -> float:
    """Digram Index of Coincidence — probability two random adjacent pairs match."""
    if len(text) < 2:
        return 0.0
    digrams = [text[i:i + 2] for i in range(len(text) - 1)]
    freq = Counter(digrams)
    n = len(digrams)
    if n <= 1:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def count_repeated_bigrams(text: str) -> int:
    """Count bigrams that appear more than once."""
    freq = Counter(text[i:i + 2] for i in range(len(text) - 1))
    return sum(1 for f in freq.values() if f > 1)


def count_repeated_trigrams(text: str) -> int:
    """Count trigrams that appear more than once."""
    freq = Counter(text[i:i + 3] for i in range(len(text) - 2))
    return sum(1 for f in freq.values() if f > 1)


def total_repeated_bigram_instances(text: str) -> int:
    """Total excess bigram repetitions (sum of (count-1) for count>1)."""
    freq = Counter(text[i:i + 2] for i in range(len(text) - 1))
    return sum(f - 1 for f in freq.values() if f > 1)


def total_repeated_trigram_instances(text: str) -> int:
    """Total excess trigram repetitions."""
    freq = Counter(text[i:i + 3] for i in range(len(text) - 2))
    return sum(f - 1 for f in freq.values() if f > 1)


def longest_repeated_substring(text: str) -> int:
    """Length of the longest substring that appears at least twice."""
    n = len(text)
    best = 0
    # Check lengths from large to small
    for length in range(min(n // 2, 15), 1, -1):
        seen = set()
        found = False
        for i in range(n - length + 1):
            sub = text[i:i + length]
            if sub in seen:
                best = max(best, length)
                found = True
                break
            seen.add(sub)
        if found and best == length:
            break
    return best


def bigram_chi_squared(text: str) -> float:
    """Chi-squared of observed bigram freq vs uniform.

    Higher = more peaked distribution = more structured (good for ciphertext
    that was generated by a substitution cipher).
    """
    digrams = [text[i:i + 2] for i in range(len(text) - 1)]
    freq = Counter(digrams)
    n = len(digrams)
    n_possible = 26 * 26
    expected = n / n_possible
    if expected == 0:
        return 0.0

    chi2 = 0.0
    for pair, count in freq.items():
        chi2 += (count - expected) ** 2 / expected
    # Add contribution from unseen bigrams
    n_seen = len(freq)
    chi2 += (n_possible - n_seen) * (expected ** 2) / expected
    return chi2


def serial_correlation(text: str) -> float:
    """Serial correlation coefficient of letter indices.

    Measures linear dependence between consecutive characters.
    Substitution of English text creates characteristic correlations
    (because English has strong digram structure: e.g., Q followed by U).
    Transposition disrupts this.
    """
    nums = [ALPH_IDX[c] for c in text]
    n = len(nums)
    if n < 2:
        return 0.0

    mean = sum(nums) / n
    var = sum((x - mean) ** 2 for x in nums) / n
    if var == 0:
        return 0.0

    cov = sum((nums[i] - mean) * (nums[i + 1] - mean) for i in range(n - 1)) / (n - 1)
    return cov / var


def even_odd_ic_diff(text: str) -> float:
    """Difference in IC between even and odd positions.

    Period-2 structure would show up as different ICs.
    """
    even = text[0::2]
    odd = text[1::2]
    return abs(ic(even) - ic(odd))


def contact_score(text: str) -> float:
    """Score adjacency contacts against English bigram expectations.

    For each adjacent pair, check if it's a common English bigram
    (after hypothetical monoalphabetic substitution — we use a proxy:
    how many of the top English bigrams map to observed bigrams).

    Actually: we measure how peaked the bigram distribution is relative
    to what English-through-monoalphabetic-substitution would produce.
    A simpler proxy: count how many distinct bigrams appear, normalized.
    Fewer distinct bigrams = more structured.
    """
    if len(text) < 2:
        return 0.0
    digrams = [text[i:i + 2] for i in range(len(text) - 1)]
    n_total = len(digrams)
    n_distinct = len(set(digrams))
    # English text has ~450-500 distinct bigrams per 96 adjacent pairs
    # Random has ~96 (almost all unique for 96 pairs from 676 possible)
    # Lower n_distinct/n_total = more structured
    return 1.0 - (n_distinct / n_total)


def max_bigram_frequency(text: str) -> int:
    """Maximum frequency of any single bigram."""
    freq = Counter(text[i:i + 2] for i in range(len(text) - 1))
    return max(freq.values()) if freq else 0


def periodic_structure_score(text: str) -> float:
    """Detect periodic structure by checking IC at various periods.

    For each period p, split text into p streams and compute average IC.
    Higher average IC at some period suggests periodic substitution structure
    is preserved.
    """
    best_avg_ic = 0.0
    for p in range(2, 15):
        streams = ["" for _ in range(p)]
        for i, c in enumerate(text):
            streams[i % p] += c
        avg_ic = sum(ic(s) for s in streams) / p
        if avg_ic > best_avg_ic:
            best_avg_ic = avg_ic
    return best_avg_ic


def compute_stats(text: str) -> Dict[str, float]:
    """Compute all statistical measures for a text."""
    return {
        'ic': ic(text),
        'digram_ic': digram_ic(text),
        'repeated_bigrams': count_repeated_bigrams(text),
        'repeated_trigrams': count_repeated_trigrams(text),
        'bigram_excess': total_repeated_bigram_instances(text),
        'trigram_excess': total_repeated_trigram_instances(text),
        'longest_repeat': longest_repeated_substring(text),
        'bigram_chi2': bigram_chi_squared(text),
        'serial_corr': serial_correlation(text),
        'even_odd_ic': even_odd_ic_diff(text),
        'contact': contact_score(text),
        'max_bigram_freq': max_bigram_frequency(text),
        'periodic_ic': periodic_structure_score(text),
    }


# ── Composite scoring ────────────────────────────────────────────────────────

def composite_transposition_score(stats: Dict[str, float],
                                   baseline: Dict[str, float]) -> float:
    """Score a candidate transposition relative to baseline (original CT).

    Higher score = more likely to be the correct untransposition.
    We reward IMPROVEMENTS over the baseline.
    """
    score = 0.0

    # 1. Digram IC improvement (weight: 30)
    #    Correct untransposition should increase digram IC
    digram_ic_delta = stats['digram_ic'] - baseline['digram_ic']
    score += digram_ic_delta * 30000.0  # scale to make meaningful

    # 2. Repeated bigrams improvement (weight: 15)
    bigram_delta = stats['repeated_bigrams'] - baseline['repeated_bigrams']
    score += bigram_delta * 1.5

    # 3. Repeated trigrams improvement (weight: 20)
    trigram_delta = stats['repeated_trigrams'] - baseline['repeated_trigrams']
    score += trigram_delta * 2.0

    # 4. Bigram excess instances (weight: 10)
    excess_delta = stats['bigram_excess'] - baseline['bigram_excess']
    score += excess_delta * 1.0

    # 5. Trigram excess instances (weight: 15)
    tri_excess_delta = stats['trigram_excess'] - baseline['trigram_excess']
    score += tri_excess_delta * 1.5

    # 6. Longest repeated substring (weight: 25)
    repeat_delta = stats['longest_repeat'] - baseline['longest_repeat']
    score += repeat_delta * 2.5

    # 7. Bigram chi-squared (more peaked = more structured)
    chi2_delta = stats['bigram_chi2'] - baseline['bigram_chi2']
    score += chi2_delta * 0.01

    # 8. Serial correlation (absolute value — more structured)
    serial_delta = abs(stats['serial_corr']) - abs(baseline['serial_corr'])
    score += serial_delta * 5.0

    # 9. Contact score improvement
    contact_delta = stats['contact'] - baseline['contact']
    score += contact_delta * 10.0

    # 10. Max bigram frequency improvement
    max_bf_delta = stats['max_bigram_freq'] - baseline['max_bigram_freq']
    score += max_bf_delta * 1.0

    # 11. Periodic IC improvement (weight: 20)
    periodic_delta = stats['periodic_ic'] - baseline['periodic_ic']
    score += periodic_delta * 200.0

    return score


# ── 73-char extraction scoring ───────────────────────────────────────────────

def best_73_char_ic(text: str, n_extract: int = 73) -> Tuple[float, float]:
    """For a given text, find the best IC achievable by selecting n_extract
    of its characters (preserving order).

    Since C(97,73) is astronomical, we use heuristics:
    1. Remove the 24 least-frequent letters (greedily)
    2. Remove letters that contribute most to IC depression
    3. Random sampling

    Returns (best_ic, baseline_ic).
    """
    baseline_ic_val = ic(text)

    # Strategy 1: Remove 24 chars that contribute least to IC
    # Heuristic: remove chars whose letter has frequency closest to average
    n = len(text)
    n_remove = n - n_extract
    freq = Counter(text)
    avg_freq = n / 26.0

    # Score each position: how much it contributes to IC-boosting frequencies
    # Letters with extreme frequencies (high or low) contribute more to IC
    # We want to KEEP those and remove "average" ones
    position_scores = []
    for i, ch in enumerate(text):
        # Deviation of this letter's count from average
        dev = abs(freq[ch] - avg_freq)
        position_scores.append((dev, i))

    # Remove positions with smallest deviation (most "average" letters)
    position_scores.sort()
    remove_set = set(pos for _, pos in position_scores[:n_remove])
    extracted = "".join(ch for i, ch in enumerate(text) if i not in remove_set)
    ic_strat1 = ic(extracted)

    # Strategy 2: Greedy removal — at each step, remove the char whose
    # removal increases IC the most (only do first few steps as approximation)
    chars = list(text)
    removed = set()
    for step in range(n_remove):
        best_ic_val = -1.0
        best_pos = -1
        remaining = [ch for i, ch in enumerate(chars) if i not in removed]
        current_ic = ic("".join(remaining))

        # Sample positions to try (all remaining if feasible, else sample)
        candidates = [i for i in range(n) if i not in removed]
        if len(candidates) > 200:
            # Too many, sample
            import random
            random.seed(42 + step)
            candidates = random.sample(candidates, 200)

        for pos in candidates:
            test_text = "".join(ch for i, ch in enumerate(chars)
                                if i not in removed and i != pos)
            test_ic = ic(test_text)
            if test_ic > best_ic_val:
                best_ic_val = test_ic
                best_pos = pos

        if best_pos >= 0:
            removed.add(best_pos)

    extracted2 = "".join(ch for i, ch in enumerate(chars) if i not in removed)
    ic_strat2 = ic(extracted2)

    return max(ic_strat1, ic_strat2), baseline_ic_val


# ── Main ─────────────────────────────────────────────────────────────────────

def attack():
    """Run the statistical transposition detector."""
    print("=" * 80)
    print("STATISTICAL TRANSPOSITION DETECTOR FOR KRYPTOS K4")
    print("=" * 80)
    print(f"\nCiphertext: {CT}")
    print(f"Length: {CT_LEN}")
    print()

    # Compute baseline statistics
    baseline = compute_stats(CT)
    print("BASELINE STATISTICS (original carved text):")
    for key, val in baseline.items():
        if isinstance(val, float):
            print(f"  {key:25s}: {val:.6f}")
        else:
            print(f"  {key:25s}: {val}")
    print()

    # Also compute stats for reversed CT
    ct_rev = CT[::-1]
    rev_stats = compute_stats(ct_rev)
    print("REVERSED CT STATISTICS (sanity check — should match IC, differ in digrams):")
    print(f"  ic: {rev_stats['ic']:.6f} (same as baseline: {rev_stats['ic'] == baseline['ic']})")
    print(f"  digram_ic: {rev_stats['digram_ic']:.6f}")
    print(f"  repeated_bigrams: {rev_stats['repeated_bigrams']}")
    print()

    # ── Collect all candidate transpositions ──────────────────────────────────

    results: List[Tuple[float, str, str, Dict[str, float]]] = []
    # Each entry: (composite_score, description, untransposed_text, stats)

    total_tested = 0
    t_start = time.time()

    # Width 4-9: brute force all permutations
    for width in range(4, 10):
        n_perms = math.factorial(width)
        t_width_start = time.time()
        width_count = 0

        for perm in permutations(range(width)):
            text = columnar_decrypt(CT, list(perm))
            stats = compute_stats(text)
            score = composite_transposition_score(stats, baseline)
            results.append((score, f"columnar(w={width}, perm={perm})", text, stats))
            total_tested += 1
            width_count += 1

        elapsed = time.time() - t_width_start
        print(f"  Width {width}: {width_count:>7,} permutations in {elapsed:.1f}s")
        sys.stdout.flush()

    # Width 10-14: keyword-based permutations
    for width in range(10, 15):
        width_count = 0
        t_width_start = time.time()

        seen_orders = set()  # avoid duplicate column orders

        for keyword in THEMATIC_KEYWORDS:
            if len(keyword) < width:
                # Try cycling
                extended = (keyword * ((width // len(keyword)) + 1))[:width]
                keywords_to_try = [keyword[:width] if len(keyword) >= width else extended]
            else:
                keywords_to_try = [keyword[:width]]

            # Also try the keyword starting at each offset
            for start in range(len(keyword)):
                rotated = keyword[start:] + keyword[:start]
                if len(rotated) >= width:
                    keywords_to_try.append(rotated[:width])
                else:
                    extended = (rotated * ((width // len(rotated)) + 1))[:width]
                    keywords_to_try.append(extended)

            for kw in keywords_to_try:
                order = keyword_to_col_order(kw, width)
                order_tuple = tuple(order)
                if order_tuple in seen_orders:
                    continue
                seen_orders.add(order_tuple)

                # Also try inverse order
                inv_order = [0] * width
                for i, v in enumerate(order):
                    inv_order[v] = i
                inv_tuple = tuple(inv_order)

                for o, label in [(order, f"kw={kw}"),
                                  (inv_order, f"kw={kw},inv")]:
                    o_tuple = tuple(o)
                    text = columnar_decrypt(CT, list(o))
                    stats = compute_stats(text)
                    score = composite_transposition_score(stats, baseline)
                    results.append((score, f"columnar(w={width}, {label})", text, stats))
                    total_tested += 1
                    width_count += 1

        elapsed = time.time() - t_width_start
        print(f"  Width {width}: {width_count:>7,} keyword permutations in {elapsed:.1f}s")
        sys.stdout.flush()

    total_elapsed = time.time() - t_start
    print(f"\nTotal tested: {total_tested:,} in {total_elapsed:.1f}s")
    print()

    # ── Sort and report ──────────────────────────────────────────────────────

    results.sort(key=lambda x: x[0], reverse=True)

    print("=" * 80)
    print("TOP 20 TRANSPOSITIONS BY COMPOSITE STATISTICAL SCORE")
    print("=" * 80)
    print()

    for rank, (score, desc, text, stats) in enumerate(results[:20], 1):
        print(f"#{rank:2d}  Score: {score:+.4f}")
        print(f"     Method: {desc}")
        print(f"     Text:   {text}")
        print(f"     digram_ic:    {stats['digram_ic']:.6f}  (baseline: {baseline['digram_ic']:.6f}  delta: {stats['digram_ic'] - baseline['digram_ic']:+.6f})")
        print(f"     rep_bigrams:  {stats['repeated_bigrams']:3d}       (baseline: {baseline['repeated_bigrams']})")
        print(f"     rep_trigrams: {stats['repeated_trigrams']:3d}       (baseline: {baseline['repeated_trigrams']})")
        print(f"     bigram_excess:{stats['bigram_excess']:3d}       (baseline: {baseline['bigram_excess']})")
        print(f"     trigram_exc:  {stats['trigram_excess']:3d}       (baseline: {baseline['trigram_excess']})")
        print(f"     longest_rep:  {stats['longest_repeat']:3d}       (baseline: {baseline['longest_repeat']})")
        print(f"     chi2:         {stats['bigram_chi2']:.2f}  (baseline: {baseline['bigram_chi2']:.2f})")
        print(f"     serial_corr:  {stats['serial_corr']:+.4f}  (baseline: {baseline['serial_corr']:+.4f})")
        print(f"     contact:      {stats['contact']:.4f}  (baseline: {baseline['contact']:.4f})")
        print(f"     max_bf:       {stats['max_bigram_freq']:3d}       (baseline: {baseline['max_bigram_freq']})")
        print(f"     periodic_ic:  {stats['periodic_ic']:.6f}  (baseline: {baseline['periodic_ic']:.6f})")
        print()

    # ── Detailed analysis tables ─────────────────────────────────────────────

    # Group top results by width
    print("=" * 80)
    print("BEST RESULT PER WIDTH")
    print("=" * 80)
    best_per_width: Dict[int, Tuple] = {}
    for score, desc, text, stats in results:
        # Extract width from description
        if "w=" in desc:
            w_str = desc.split("w=")[1].split(",")[0].split(")")[0]
            try:
                w = int(w_str)
            except ValueError:
                continue
            if w not in best_per_width:
                best_per_width[w] = (score, desc, text, stats)

    print(f"\n{'Width':>5s} {'Score':>10s} {'Digram IC':>10s} {'Rep Bi':>7s} {'Rep Tri':>7s} {'LRS':>4s} {'Chi2':>8s} {'Ser.Corr':>9s} {'Per.IC':>8s} Method")
    print("-" * 120)
    for w in sorted(best_per_width.keys()):
        score, desc, text, stats = best_per_width[w]
        # Truncate method
        method_short = desc.replace("columnar(", "").rstrip(")")
        if len(method_short) > 40:
            method_short = method_short[:37] + "..."
        print(f"{w:5d} {score:+10.4f} {stats['digram_ic']:10.6f} {stats['repeated_bigrams']:7d} {stats['repeated_trigrams']:7d} {stats['longest_repeat']:4d} {stats['bigram_chi2']:8.2f} {stats['serial_corr']:+9.4f} {stats['periodic_ic']:8.6f} {method_short}")

    print()

    # ── Specific metric leaders ──────────────────────────────────────────────

    print("=" * 80)
    print("TOP 5 BY INDIVIDUAL METRICS")
    print("=" * 80)

    metrics = [
        ('digram_ic', 'Digram IC', True),
        ('repeated_bigrams', 'Repeated Bigrams', True),
        ('repeated_trigrams', 'Repeated Trigrams', True),
        ('longest_repeat', 'Longest Repeated Substr', True),
        ('bigram_chi2', 'Bigram Chi-Squared', True),
        ('periodic_ic', 'Periodic IC (best period)', True),
        ('trigram_excess', 'Trigram Excess Instances', True),
    ]

    for metric_key, metric_name, higher_better in metrics:
        sorted_by = sorted(results, key=lambda x: x[3][metric_key], reverse=higher_better)
        print(f"\n  --- {metric_name} (baseline={baseline[metric_key]}) ---")
        for i, (score, desc, text, stats) in enumerate(sorted_by[:5], 1):
            val = stats[metric_key]
            delta = val - baseline[metric_key]
            method_short = desc[:70]
            print(f"    #{i}: {val:.6f} (delta={delta:+.6f})  {method_short}")

    print()

    # ── 73-char extraction test on top candidates ────────────────────────────

    print("=" * 80)
    print("73-CHAR EXTRACTION TEST ON TOP 10 CANDIDATES")
    print("(Find best IC achievable by selecting 73 of 97 chars)")
    print("=" * 80)
    print()

    # Baseline 73-char IC
    base_73_ic, _ = best_73_char_ic(CT)
    print(f"Baseline CT: best 73-char IC = {base_73_ic:.6f}  (full 97-char IC = {baseline['ic']:.6f})")
    print()

    for rank, (score, desc, text, stats) in enumerate(results[:10], 1):
        ext_ic, full_ic = best_73_char_ic(text)
        delta_from_base = ext_ic - base_73_ic
        print(f"  #{rank}: 73-char IC = {ext_ic:.6f}  (delta from baseline 73-char: {delta_from_base:+.6f})")
        print(f"       {desc[:70]}")
    print()

    # ── Check for consensus ──────────────────────────────────────────────────

    print("=" * 80)
    print("CONSENSUS ANALYSIS")
    print("=" * 80)
    print()

    # For each metric, record the top-3 widths and permutations
    # Then check if any width/perm appears in top-3 for multiple metrics
    metric_tops: Dict[str, List[str]] = {}
    for metric_key, metric_name, higher_better in metrics:
        sorted_by = sorted(results, key=lambda x: x[3][metric_key], reverse=higher_better)
        metric_tops[metric_key] = [entry[1] for entry in sorted_by[:5]]

    # Count how many times each description appears in top-5 across metrics
    desc_counts: Counter = Counter()
    for key, descs in metric_tops.items():
        for d in descs:
            desc_counts[d] += 1

    print("Candidates appearing in top-5 for MULTIPLE metrics:")
    for desc, count in desc_counts.most_common(20):
        if count >= 2:
            # Find its composite score
            for s, d, t, st in results:
                if d == desc:
                    print(f"  [{count} metrics] Score={s:+.4f}  {desc[:80]}")
                    break
    print()

    # ── Summary statistics ───────────────────────────────────────────────────

    print("=" * 80)
    print("DISTRIBUTION ANALYSIS")
    print("=" * 80)
    print()

    all_scores = [r[0] for r in results]
    n_scores = len(all_scores)
    mean_s = sum(all_scores) / n_scores
    sum_sq = sum((s - mean_s) ** 2 for s in all_scores)
    std_s = (sum_sq / n_scores) ** 0.5
    min_s = min(all_scores)
    max_s = max(all_scores)

    print(f"Score distribution across {n_scores:,} candidates:")
    print(f"  Mean:   {mean_s:+.4f}")
    print(f"  StdDev: {std_s:.4f}")
    print(f"  Min:    {min_s:+.4f}")
    print(f"  Max:    {max_s:+.4f}")
    print(f"  Top 1:  {results[0][0]:+.4f} ({results[0][1][:60]})")

    if std_s > 0:
        z_top = (results[0][0] - mean_s) / std_s
        print(f"  Top z-score: {z_top:.2f} standard deviations above mean")
    print()

    # Histogram of scores
    print("Score histogram (20 bins):")
    n_bins = 20
    bin_w = (max_s - min_s) / n_bins if max_s > min_s else 1.0
    bins = [0] * n_bins
    for s in all_scores:
        b = min(int((s - min_s) / bin_w), n_bins - 1)
        bins[b] += 1

    max_bin = max(bins) if bins else 1
    for i, count in enumerate(bins):
        lo = min_s + i * bin_w
        hi = lo + bin_w
        bar_len = int(50 * count / max_bin) if max_bin > 0 else 0
        bar = "#" * bar_len
        print(f"  [{lo:+7.2f}, {hi:+7.2f}): {count:6d} {bar}")

    print()
    print("=" * 80)
    print("DONE")
    print("=" * 80)

    return results


if __name__ == "__main__":
    results = attack()
