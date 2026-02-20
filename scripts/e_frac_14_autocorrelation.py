#!/usr/bin/env python3
"""E-FRAC-14: K4 Autocorrelation Deep Dive

K4 has a significant lag-7 autocorrelation (z=3.04, 9 matches vs ~3.5 expected).
This experiment:
1. Computes autocorrelation at ALL lags (1-48) and tests significance
2. Identifies specific lag-7 matching positions and their structure
3. Determines what transposition families create the observed autocorrelation profile
4. Tests whether the lag-7 signal survives under specific un-transpositions
5. Provides a comprehensive statistical fingerprint for cipher family discrimination

This analysis should help constrain the transposition layer (if any).
"""

import json
import math
import os
import random
import time
from collections import Counter
from pathlib import Path

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD, ALPH_IDX, CRIB_DICT,
    IC_K4, IC_RANDOM, IC_ENGLISH,
)


def letter_to_num(text: str) -> list[int]:
    """Convert text to list of 0-25 values."""
    return [ALPH_IDX[c] for c in text]


def autocorrelation_matches(text: str, lag: int) -> list[int]:
    """Return positions where text[i] == text[i+lag]."""
    return [i for i in range(len(text) - lag) if text[i] == text[i + lag]]


def autocorrelation_count(text: str, lag: int) -> int:
    """Count positions where text[i] == text[i+lag]."""
    return sum(1 for i in range(len(text) - lag) if text[i] == text[i + lag])


def random_text(length: int) -> str:
    return ''.join(random.choice(ALPH) for _ in range(length))


def generate_english_like(length: int) -> str:
    freqs = {
        'E': 0.127, 'T': 0.091, 'A': 0.082, 'O': 0.075, 'I': 0.070,
        'N': 0.067, 'S': 0.063, 'H': 0.061, 'R': 0.060, 'D': 0.043,
        'L': 0.040, 'C': 0.028, 'U': 0.028, 'M': 0.024, 'W': 0.024,
        'F': 0.022, 'G': 0.020, 'Y': 0.020, 'P': 0.019, 'B': 0.015,
        'V': 0.010, 'K': 0.008, 'J': 0.002, 'X': 0.002, 'Q': 0.001,
        'Z': 0.001,
    }
    letters = list(freqs.keys())
    weights = [freqs[l] for l in letters]
    return ''.join(random.choices(letters, weights=weights, k=length))


def columnar_transpose(text: str, width: int, col_order: list[int]) -> str:
    """Apply columnar transposition: write across width, read columns in col_order."""
    n = len(text)
    n_full_rows = n // width
    n_extra = n % width
    # Build columns
    cols = []
    for col in range(width):
        col_chars = []
        for row in range(n_full_rows + (1 if col < n_extra else 0)):
            pos = row * width + col
            if pos < n:
                col_chars.append(text[pos])
        cols.append(''.join(col_chars))
    # Read in col_order
    return ''.join(cols[col_order[i]] for i in range(width))


def columnar_perm(text: str, width: int, col_order: list[int]) -> list[int]:
    """Return the permutation array for columnar transposition."""
    n = len(text)
    n_full_rows = n // width
    n_extra = n % width
    perm = []
    for read_col_idx in range(width):
        actual_col = col_order[read_col_idx]
        n_rows = n_full_rows + (1 if actual_col < n_extra else 0)
        for row in range(n_rows):
            perm.append(row * width + actual_col)
    return perm


def apply_perm(text: str, perm: list[int]) -> str:
    """output[i] = input[perm[i]] (gather convention)."""
    return ''.join(text[perm[i]] for i in range(len(perm)))


def invert_perm(perm: list[int]) -> list[int]:
    """Compute inverse permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def main():
    start_time = time.time()
    random.seed(42)
    results = {}
    nums = letter_to_num(CT)

    print("=" * 70)
    print("E-FRAC-14: K4 Autocorrelation Deep Dive")
    print("=" * 70)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 1: Full autocorrelation profile (lags 1-48)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 1: K4 autocorrelation at all lags ---")

    N_MC = 200_000

    # Compute K4 autocorrelation at each lag
    lag_results = {}
    significant_lags = []

    for lag in range(1, 49):
        n_pairs = CT_LEN - lag
        matches = autocorrelation_count(CT, lag)
        expected = n_pairs / 26.0
        # Use Monte Carlo for exact p-value
        mc_counts = []
        for _ in range(N_MC):
            rt = random_text(CT_LEN)
            mc_counts.append(autocorrelation_count(rt, lag))
        mc_mean = sum(mc_counts) / len(mc_counts)
        mc_std = (sum((x - mc_mean) ** 2 for x in mc_counts) / len(mc_counts)) ** 0.5
        z = (matches - mc_mean) / mc_std if mc_std > 0 else 0
        p_upper = sum(1 for x in mc_counts if x >= matches) / len(mc_counts)

        lag_results[lag] = {
            'matches': matches,
            'n_pairs': n_pairs,
            'expected': round(expected, 2),
            'mc_mean': round(mc_mean, 3),
            'mc_std': round(mc_std, 3),
            'z_score': round(z, 3),
            'p_upper': p_upper,
        }

        marker = ""
        if p_upper < 0.01:
            marker = " ***"
            significant_lags.append(lag)
        elif p_upper < 0.05:
            marker = " **"
            significant_lags.append(lag)

        if matches >= expected * 1.5 or matches == 0 or lag <= 10 or marker:
            print(f"  Lag {lag:2d}: {matches:2d} matches (exp {expected:.1f}, z={z:+.2f}, p={p_upper:.4f}){marker}")

    # Multiple testing correction (Bonferroni)
    print(f"\n  Significant lags (p < 0.05, uncorrected): {significant_lags}")
    bonferroni_sig = [l for l in significant_lags if lag_results[l]['p_upper'] < 0.05 / 48]
    print(f"  Significant after Bonferroni (p < {0.05/48:.5f}): {bonferroni_sig}")

    results['part1_autocorrelation'] = {
        'lags': {str(k): v for k, v in lag_results.items()},
        'significant_uncorrected': significant_lags,
        'significant_bonferroni': bonferroni_sig,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 2: Specific lag-7 matching positions
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 2: Lag-7 matching positions ---")
    lag7_pos = autocorrelation_matches(CT, 7)
    print(f"  Lag-7 matches: {len(lag7_pos)} positions")
    for pos in lag7_pos:
        in_crib_i = pos in CRIB_DICT
        in_crib_i7 = (pos + 7) in CRIB_DICT
        crib_note = ""
        if in_crib_i or in_crib_i7:
            crib_note = f" [crib at {'pos' if in_crib_i else ''}{'+' if in_crib_i and in_crib_i7 else ''}{'pos+7' if in_crib_i7 else ''}]"
        print(f"    pos {pos:2d}: CT[{pos}]='{CT[pos]}' == CT[{pos + 7}]='{CT[pos + 7]}'{crib_note}")

    # Distribution of gaps between lag-7 matches
    if len(lag7_pos) > 1:
        gaps = [lag7_pos[i + 1] - lag7_pos[i] for i in range(len(lag7_pos) - 1)]
        print(f"  Gaps between matches: {gaps}")
        print(f"  Match density (positions per match): {(CT_LEN - 7) / len(lag7_pos):.1f}")

    # Are lag-7 matches in the crib regions?
    crib_lag7 = [p for p in lag7_pos if p in CRIB_DICT or (p + 7) in CRIB_DICT]
    print(f"  Of {len(lag7_pos)} matches, {len(crib_lag7)} involve crib positions")

    results['part2_lag7'] = {
        'positions': lag7_pos,
        'letters': [(CT[p], CT[p + 7]) for p in lag7_pos],
        'gaps': [lag7_pos[i + 1] - lag7_pos[i] for i in range(len(lag7_pos) - 1)] if len(lag7_pos) > 1 else [],
        'crib_involved': len(crib_lag7),
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 3: Bigram / trigram frequency analysis
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 3: Bigram frequency analysis ---")

    bigrams = [CT[i:i + 2] for i in range(CT_LEN - 1)]
    bigram_counts = Counter(bigrams)

    # Repeated bigrams (count > 1)
    repeated = {bg: c for bg, c in bigram_counts.items() if c > 1}
    print(f"  Total bigrams: {len(bigrams)}")
    print(f"  Unique bigrams: {len(bigram_counts)}")
    print(f"  Repeated bigrams ({len(repeated)}):")
    for bg, c in sorted(repeated.items(), key=lambda x: -x[1])[:15]:
        print(f"    '{bg}' × {c}")

    # Compare repeated bigram count with random expectation
    mc_repeated = []
    for _ in range(100_000):
        rt = random_text(CT_LEN)
        bgs = Counter(rt[i:i + 2] for i in range(CT_LEN - 1))
        mc_repeated.append(sum(1 for c in bgs.values() if c > 1))
    mc_mean_rep = sum(mc_repeated) / len(mc_repeated)
    mc_std_rep = (sum((x - mc_mean_rep) ** 2 for x in mc_repeated) / len(mc_repeated)) ** 0.5
    z_rep = (len(repeated) - mc_mean_rep) / mc_std_rep if mc_std_rep > 0 else 0
    print(f"  Repeated bigrams: {len(repeated)} (random: {mc_mean_rep:.1f} ± {mc_std_rep:.1f}, z={z_rep:+.2f})")

    # IC on bigrams
    bg_ic = sum(c * (c - 1) for c in bigram_counts.values()) / (len(bigrams) * (len(bigrams) - 1)) if len(bigrams) > 1 else 0
    print(f"  Bigram IC: {bg_ic:.6f}")

    # Trigram analysis
    trigrams = [CT[i:i + 3] for i in range(CT_LEN - 2)]
    trigram_counts = Counter(trigrams)
    repeated_tri = {tg: c for tg, c in trigram_counts.items() if c > 1}
    print(f"\n  Repeated trigrams ({len(repeated_tri)}):")
    for tg, c in sorted(repeated_tri.items(), key=lambda x: -x[1]):
        # Find positions
        positions = [i for i in range(CT_LEN - 2) if CT[i:i + 3] == tg]
        print(f"    '{tg}' × {c} at positions {positions}")

    results['part3_ngrams'] = {
        'n_unique_bigrams': len(bigram_counts),
        'n_repeated_bigrams': len(repeated),
        'bigram_ic': bg_ic,
        'top_bigrams': dict(bigram_counts.most_common(10)),
        'repeated_bigrams': repeated,
        'repeated_trigrams': {k: v for k, v in repeated_tri.items()},
        'z_repeated_bigrams': z_rep,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 4: DFT analysis of the letter-number sequence
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 4: DFT spectrum of CT letter values ---")

    # Center the sequence
    mean_val = sum(nums) / len(nums)
    centered = [x - mean_val for x in nums]

    # DFT (manual for small N)
    N = len(centered)
    magnitudes = []
    for k in range(1, N // 2 + 1):
        real_part = sum(centered[n] * math.cos(2 * math.pi * k * n / N) for n in range(N))
        imag_part = sum(centered[n] * math.sin(2 * math.pi * k * n / N) for n in range(N))
        mag = math.sqrt(real_part ** 2 + imag_part ** 2)
        magnitudes.append((k, mag))

    # Monte Carlo for significance
    mc_max_mags = []
    N_DFT_MC = 50_000
    for _ in range(N_DFT_MC):
        rt_nums = [random.randint(0, 25) for _ in range(N)]
        rt_mean = sum(rt_nums) / N
        rt_centered = [x - rt_mean for x in rt_nums]
        rt_max_mag = 0
        for k in range(1, N // 2 + 1):
            rp = sum(rt_centered[n] * math.cos(2 * math.pi * k * n / N) for n in range(N))
            ip = sum(rt_centered[n] * math.sin(2 * math.pi * k * n / N) for n in range(N))
            m = math.sqrt(rp ** 2 + ip ** 2)
            if m > rt_max_mag:
                rt_max_mag = m
        mc_max_mags.append(rt_max_mag)

    mc_max_mags.sort()
    mc_95 = mc_max_mags[int(0.95 * N_DFT_MC)]
    mc_99 = mc_max_mags[int(0.99 * N_DFT_MC)]

    magnitudes.sort(key=lambda x: -x[1])
    print(f"  Top 10 DFT peaks (max-peak 95th/99th random: {mc_95:.1f}/{mc_99:.1f}):")
    for k, mag in magnitudes[:10]:
        period = N / k if k > 0 else float('inf')
        sig = " ***" if mag > mc_99 else " **" if mag > mc_95 else ""
        print(f"    k={k:2d} (period {period:5.1f}): magnitude = {mag:.2f}{sig}")

    results['part4_dft'] = {
        'top_10': [(k, mag) for k, mag in magnitudes[:10]],
        'mc_95': mc_95,
        'mc_99': mc_99,
        'n_significant_99': sum(1 for k, m in magnitudes if m > mc_99),
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 5: What transpositions create K4's autocorrelation profile?
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 5: Transposition families vs lag-7 ---")

    # For various transposition types, check if undoing them REMOVES lag-7
    # If transposition T was applied to get CT, then T^(-1)(CT) = intermediate
    # If intermediate has NO excess lag-7, that's consistent with T being correct

    k4_lag7 = autocorrelation_count(CT, 7)
    print(f"  K4 lag-7 matches: {k4_lag7}")

    # Random baseline for intermediate lag-7
    print(f"\n  After un-transposing with random permutations (N=100K):")
    mc_lag7_after = []
    for _ in range(100_000):
        perm = list(range(CT_LEN))
        random.shuffle(perm)
        untrans = apply_perm(CT, perm)
        mc_lag7_after.append(autocorrelation_count(untrans, 7))
    mc_mean_after = sum(mc_lag7_after) / len(mc_lag7_after)
    mc_std_after = (sum((x - mc_mean_after) ** 2 for x in mc_lag7_after) / len(mc_lag7_after)) ** 0.5
    print(f"    Mean lag-7 after: {mc_mean_after:.2f} ± {mc_std_after:.2f}")
    print(f"    P(lag-7 ≤ 3) = {sum(1 for x in mc_lag7_after if x <= 3) / len(mc_lag7_after):.3f}")
    print(f"    P(lag-7 = 0) = {sum(1 for x in mc_lag7_after if x == 0) / len(mc_lag7_after):.3f}")

    # Columnar transpositions at various widths
    print(f"\n  Columnar un-transpositions (all orderings, what fraction removes lag-7):")
    import itertools
    col_results = {}
    for width in [5, 6, 7, 8, 9, 10]:
        # For small widths, enumerate all orderings
        if math.factorial(width) <= 100_000:
            n_reduce = 0
            n_total = 0
            best_reduction = (k4_lag7, None)
            for ordering in itertools.permutations(range(width)):
                perm = columnar_perm(CT, width, list(ordering))
                inv = invert_perm(perm)
                untrans = apply_perm(CT, inv)
                lag7 = autocorrelation_count(untrans, 7)
                n_total += 1
                if lag7 < k4_lag7:
                    n_reduce += 1
                if lag7 < best_reduction[0]:
                    best_reduction = (lag7, list(ordering))
            pct_reduce = n_reduce / n_total * 100
            print(f"    Width {width}: {n_reduce}/{n_total} ({pct_reduce:.1f}%) reduce lag-7, "
                  f"best: {best_reduction[0]} matches (ordering {best_reduction[1]})")
            col_results[width] = {
                'n_total': n_total, 'n_reduce': n_reduce,
                'pct_reduce': pct_reduce,
                'best_lag7': best_reduction[0],
                'best_ordering': best_reduction[1],
            }
        else:
            # Sample
            n_reduce = 0
            n_total = 50_000
            best_reduction = (k4_lag7, None)
            for _ in range(n_total):
                ordering = list(range(width))
                random.shuffle(ordering)
                perm = columnar_perm(CT, width, ordering)
                inv = invert_perm(perm)
                untrans = apply_perm(CT, inv)
                lag7 = autocorrelation_count(untrans, 7)
                if lag7 < k4_lag7:
                    n_reduce += 1
                if lag7 < best_reduction[0]:
                    best_reduction = (lag7, ordering)
            pct_reduce = n_reduce / n_total * 100
            print(f"    Width {width}: ~{pct_reduce:.1f}% reduce lag-7 (sampled {n_total}), "
                  f"best: {best_reduction[0]} matches")
            col_results[width] = {
                'n_total': n_total, 'n_reduce': n_reduce,
                'pct_reduce': pct_reduce,
                'best_lag7': best_reduction[0],
                'best_ordering': best_reduction[1],
                'sampled': True,
            }

    results['part5_transposition_lag7'] = {
        'k4_lag7': k4_lag7,
        'random_untrans_mean': mc_mean_after,
        'random_untrans_std': mc_std_after,
        'columnar': {str(k): v for k, v in col_results.items()},
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 6: Full autocorrelation profile under un-transposition
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 6: Does any width remove lag-7 while preserving 'normal' profile? ---")

    # For the best lag-7-reducing orderings at each width, check the full autocorrelation profile
    for width in [7, 9]:
        best_ordering = col_results[width]['best_ordering']
        if best_ordering is None:
            continue
        perm = columnar_perm(CT, width, best_ordering)
        inv = invert_perm(perm)
        untrans = apply_perm(CT, inv)

        print(f"\n  Width-{width} best ordering {best_ordering}:")
        print(f"    Intermediate: {untrans[:30]}...")

        # Full autocorrelation profile of the un-transposed text
        print(f"    Autocorrelation profile (selected lags):")
        for test_lag in [1, 2, 3, 5, 7, 9, 14, 21]:
            matches = autocorrelation_count(untrans, test_lag)
            exp = (CT_LEN - test_lag) / 26.0
            print(f"      Lag {test_lag:2d}: {matches:2d} matches (exp {exp:.1f})")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 7: Difference sequence analysis
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 7: Difference sequence analysis ---")

    diffs = [(nums[i + 1] - nums[i]) % 26 for i in range(len(nums) - 1)]
    diff_counts = Counter(diffs)
    print(f"  First-order differences (mod 26):")
    # Expected: uniform if cipher is complex enough
    diff_mean = sum(diff_counts.values()) / 26
    diff_chi2 = sum((diff_counts.get(d, 0) - diff_mean) ** 2 / diff_mean for d in range(26))
    print(f"  Chi2 vs uniform: {diff_chi2:.2f} (df=25, 5% critical = 37.65)")
    if diff_chi2 < 37.65:
        print(f"  → First-order differences are UNIFORM")
    else:
        print(f"  → First-order differences are NOT uniform")
        # Which differences are overrepresented?
        sorted_diffs = sorted(diff_counts.items(), key=lambda x: -x[1])
        for d, c in sorted_diffs[:5]:
            print(f"    Δ={d:2d}: count={c} (exp {diff_mean:.1f})")

    results['part7_differences'] = {
        'chi2_vs_uniform': diff_chi2,
        'uniform': diff_chi2 < 37.65,
        'counts': dict(diff_counts),
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 8: Known keystream structure analysis
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 8: Known keystream structure ---")

    # Vigenere key values at crib positions
    vig_key = {}
    for pos, pt_char in CRIB_DICT.items():
        ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[pt_char]
        k_vig = (ct_val - pt_val) % 26
        k_beau = (ct_val + pt_val) % 26
        vig_key[pos] = {'vig': k_vig, 'beau': k_beau}

    # Check for patterns in keystream
    vig_vals = [(pos, vig_key[pos]['vig']) for pos in sorted(vig_key.keys())]
    beau_vals = [(pos, vig_key[pos]['beau']) for pos in sorted(vig_key.keys())]

    print(f"  Vigenere key at crib positions:")
    print(f"    " + " ".join(f"{ALPH[v]}" for _, v in vig_vals))
    print(f"    " + " ".join(f"{v:2d}" for _, v in vig_vals))

    print(f"\n  Beaufort key at crib positions:")
    print(f"    " + " ".join(f"{ALPH[v]}" for _, v in beau_vals))
    print(f"    " + " ".join(f"{v:2d}" for _, v in beau_vals))

    # Key differences (between consecutive crib positions)
    print(f"\n  Key differences (consecutive crib positions, Vig):")
    for i in range(len(vig_vals) - 1):
        pos1, k1 = vig_vals[i]
        pos2, k2 = vig_vals[i + 1]
        dk = (k2 - k1) % 26
        dp = pos2 - pos1
        print(f"    pos {pos1}->{pos2} (Δpos={dp}): Δk = {dk} ({ALPH[dk]})")

    # Check if key values at positions i and i+7 match (lag-7 in key)
    print(f"\n  Key values at positions differing by 7:")
    for pos1 in sorted(vig_key.keys()):
        pos2 = pos1 + 7
        if pos2 in vig_key:
            k1 = vig_key[pos1]['vig']
            k2 = vig_key[pos2]['vig']
            match = "MATCH" if k1 == k2 else f"diff={abs(k1 - k2)}"
            print(f"    pos {pos1}/{pos2}: k={k1}/{k2} ({match})")

    # Check for modular linear relationship: k[i] = a*i + b (mod 26)
    print(f"\n  Testing k[i] = a*i + b (mod 26):")
    best_linear = (0, 0, 0)  # (matches, a, b)
    for a in range(26):
        for b in range(26):
            matches = sum(1 for pos, kv in vig_vals if (a * pos + b) % 26 == kv)
            if matches > best_linear[0]:
                best_linear = (matches, a, b)
    print(f"    Best linear fit: k[i] = {best_linear[1]}*i + {best_linear[2]} (mod 26), "
          f"{best_linear[0]}/24 matches")

    # Check quadratic: k[i] = a*i^2 + b*i + c (mod 26)
    print(f"\n  Testing k[i] = a*i² + b*i + c (mod 26):")
    best_quad = (0, 0, 0, 0)
    for a in range(26):
        for b in range(26):
            for c in range(26):
                matches = sum(1 for pos, kv in vig_vals if (a * pos * pos + b * pos + c) % 26 == kv)
                if matches > best_quad[0]:
                    best_quad = (matches, a, b, c)
    print(f"    Best quadratic: k[i] = {best_quad[1]}*i² + {best_quad[2]}*i + {best_quad[3]} (mod 26), "
          f"{best_quad[0]}/24 matches")

    # Random baseline for linear/quadratic fits
    mc_linear = []
    mc_quad = []
    for _ in range(10_000):
        fake_keys = [(pos, random.randint(0, 25)) for pos, _ in vig_vals]
        best_l = max(sum(1 for pos, kv in fake_keys if (a * pos + b) % 26 == kv)
                     for a in range(26) for b in range(26))
        mc_linear.append(best_l)
        # Quadratic too expensive for MC; just do linear
    mc_lin_mean = sum(mc_linear) / len(mc_linear)
    mc_lin_std = (sum((x - mc_lin_mean) ** 2 for x in mc_linear) / len(mc_linear)) ** 0.5
    print(f"    Random baseline (linear): {mc_lin_mean:.1f} ± {mc_lin_std:.1f}")

    results['part8_keystream'] = {
        'best_linear': {'matches': best_linear[0], 'a': best_linear[1], 'b': best_linear[2]},
        'best_quadratic': {'matches': best_quad[0], 'a': best_quad[1], 'b': best_quad[2], 'c': best_quad[3]},
        'random_linear_mean': mc_lin_mean,
        'random_linear_std': mc_lin_std,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Summary
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    runtime = time.time() - start_time

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(f"\n1. Autocorrelation:")
    print(f"   Significant lags (uncorrected p<0.05): {significant_lags}")
    print(f"   Significant after Bonferroni: {bonferroni_sig}")
    if 7 in bonferroni_sig:
        print(f"   → Lag-7 REMAINS significant after multiple testing correction")
    elif 7 in significant_lags:
        print(f"   → Lag-7 is nominally significant but does NOT survive Bonferroni correction")
    else:
        print(f"   → Lag-7 is NOT significant even uncorrected")

    print(f"\n2. Lag-7 specific matches: {len(lag7_pos)} at positions {lag7_pos}")
    print(f"   {len(crib_lag7)} involve crib positions")

    print(f"\n3. DFT: {results['part4_dft']['n_significant_99']} peaks exceed 99th percentile of random max")

    print(f"\n4. Keystream: best linear fit {best_linear[0]}/24 (random: {mc_lin_mean:.1f}±{mc_lin_std:.1f})")
    print(f"   Best quadratic fit {best_quad[0]}/24")

    print(f"\n5. First-order differences: {'UNIFORM' if diff_chi2 < 37.65 else 'NOT UNIFORM'} (chi2={diff_chi2:.1f})")

    print(f"\nRuntime: {runtime:.1f}s")
    print(f"RESULT: Autocorrelation analysis complete. Significant lags after Bonferroni: {bonferroni_sig}")

    results['summary'] = {
        'significant_lags_uncorrected': significant_lags,
        'significant_lags_bonferroni': bonferroni_sig,
        'lag7_positions': lag7_pos,
        'best_linear_key_fit': best_linear[0],
        'best_quadratic_key_fit': best_quad[0],
        'dft_significant_peaks': results['part4_dft']['n_significant_99'],
        'runtime': runtime,
    }

    # Save results
    out_dir = Path("results/frac")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "e_frac_14_autocorrelation.json"
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
