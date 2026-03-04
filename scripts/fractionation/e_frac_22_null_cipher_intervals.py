#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-22: Null Cipher / Interval Reading Analysis

Tests whether K4 contains a hidden message readable by:
1. Taking every Nth character (decimation) for N = 2..25
2. Starting from different offsets (0..N-1)
3. Reading characters at positions determined by arithmetic progressions

For each decimation, check:
- IC of the extracted sequence
- Frequency correlation with English
- Whether any common English words appear
- Quadgram score if available

This also tests whether the ciphertext has a hidden periodic structure
that would be visible through decimation (related to transposition detection).

Additionally: test whether K4 characters at positions that form specific
geometric patterns on a grid contain English text.
"""

import json
import math
import os
import random
import time
from collections import Counter

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX

ENGLISH_FREQ = {
    'A': 0.0817, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}


def compute_ic(text: str) -> float:
    """Compute index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def frequency_correlation(text: str) -> float:
    """Correlation between text frequency and English frequency."""
    n = len(text)
    if n == 0:
        return 0.0
    counts = Counter(text)
    text_freq = [counts.get(c, 0) / n for c in ALPH]
    eng_freq = [ENGLISH_FREQ[c] for c in ALPH]

    mean_t = sum(text_freq) / 26
    mean_e = sum(eng_freq) / 26

    cov = sum((t - mean_t) * (e - mean_e) for t, e in zip(text_freq, eng_freq))
    var_t = sum((t - mean_t) ** 2 for t in text_freq)
    var_e = sum((e - mean_e) ** 2 for e in eng_freq)

    if var_t == 0 or var_e == 0:
        return 0.0
    return cov / math.sqrt(var_t * var_e)


def find_english_words(text: str, min_len: int = 4) -> list:
    """Find common English words in text (simple check)."""
    common_words = [
        'THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN',
        'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'HAD', 'HAS', 'HIS',
        'HOW', 'MAN', 'NEW', 'NOW', 'OLD', 'SEE', 'WAY', 'WHO', 'BOY',
        'ITS', 'SAY', 'SHE', 'TOO', 'USE', 'THAT', 'WITH', 'HAVE', 'THIS',
        'WILL', 'YOUR', 'FROM', 'THEY', 'BEEN', 'SAID', 'EACH', 'SOME',
        'THEM', 'THAN', 'FIND', 'BEEN', 'MANY', 'THEN', 'VERY', 'WHEN',
        'COME', 'HERE', 'JUST', 'LIKE', 'LONG', 'MAKE', 'MUCH', 'OVER',
        'SUCH', 'TAKE', 'TIME', 'EAST', 'NORTH', 'SOUTH', 'WEST',
        'CLOCK', 'BERLIN', 'SECRET', 'HIDDEN', 'CODE', 'KEY', 'CIA',
        'POINT', 'LAYER', 'BETWEEN', 'SLOWLY', 'BURIED',
    ]
    found = []
    for word in common_words:
        if len(word) >= min_len and word in text:
            pos = text.index(word)
            found.append((word, pos))
    return found


def main():
    t0 = time.time()
    random.seed(42)

    print("=" * 70)
    print("E-FRAC-22: Null Cipher / Interval Reading Analysis")
    print("=" * 70)

    results = {}

    # ── Section 1: Decimation (every Nth character) ──────────────────────
    print("\n--- Section 1: Decimation — every Nth character ---")
    print(f"{'N':>3} {'Off':>3} {'Len':>3} {'IC':>7} {'FCor':>7} {'Text':>30} {'Words'}")
    print("-" * 90)

    decimation_results = []
    interesting = []

    for n in range(2, 26):
        for offset in range(n):
            positions = list(range(offset, CT_LEN, n))
            text = ''.join(CT[i] for i in positions)

            if len(text) < 4:
                continue

            ic = compute_ic(text)
            fcorr = frequency_correlation(text)
            words = find_english_words(text, min_len=3)

            entry = {
                'n': n, 'offset': offset, 'length': len(text),
                'ic': ic, 'freq_corr': fcorr,
                'text': text, 'words': words,
            }
            decimation_results.append(entry)

            # Flag interesting results
            is_interesting = ic > 0.06 or fcorr > 0.4 or len(words) > 0
            if is_interesting:
                interesting.append(entry)
                word_str = ", ".join(w for w, _ in words) if words else ""
                text_show = text[:30] + ("..." if len(text) > 30 else "")
                print(f"{n:>3} {offset:>3} {len(text):>3} {ic:>7.4f} {fcorr:>7.3f} "
                      f"{text_show:>30} {word_str}")

    results['decimation'] = {
        'total_tested': len(decimation_results),
        'interesting_count': len(interesting),
    }

    if not interesting:
        print("  (No interesting decimations found)")

    # ── Section 2: Monte Carlo calibration ───────────────────────────────
    print("\n--- Section 2: How many decimations have high IC by chance? ---")

    n_mc = 5000
    mc_high_ic = []  # count of decimations with IC > 0.06 per random CT

    for _ in range(n_mc):
        rand_ct = ''.join(random.choice(ALPH) for _ in range(CT_LEN))
        count = 0
        for n in range(2, 26):
            for offset in range(n):
                positions = list(range(offset, CT_LEN, n))
                text = ''.join(rand_ct[i] for i in positions)
                if len(text) >= 4 and compute_ic(text) > 0.06:
                    count += 1
        mc_high_ic.append(count)

    k4_high_ic = sum(1 for e in decimation_results if e['ic'] > 0.06)
    mean_mc = sum(mc_high_ic) / len(mc_high_ic)
    std_mc = math.sqrt(sum((x - mean_mc) ** 2 for x in mc_high_ic) / len(mc_high_ic))
    pctile = sum(1 for x in mc_high_ic if x <= k4_high_ic) / n_mc * 100

    print(f"  K4 decimations with IC > 0.06: {k4_high_ic}")
    print(f"  Random CT: mean={mean_mc:.1f}, std={std_mc:.1f}")
    print(f"  K4 percentile: {pctile:.1f}%")

    results['mc_calibration'] = {
        'k4_high_ic_count': k4_high_ic,
        'random_mean': mean_mc,
        'random_std': std_mc,
        'percentile': pctile,
    }

    # ── Section 3: Caesar-shifted decimations ────────────────────────────
    print("\n--- Section 3: Caesar-shifted decimations ---")
    print("  For each decimation, try all 26 Caesar shifts and check for English:")

    shifted_interesting = []
    for n in range(2, 16):
        for offset in range(n):
            positions = list(range(offset, CT_LEN, n))
            text = ''.join(CT[i] for i in positions)
            if len(text) < 8:
                continue

            for shift in range(26):
                shifted = ''.join(ALPH[(ALPH_IDX[c] + shift) % 26] for c in text)
                fcorr = frequency_correlation(shifted)
                words = find_english_words(shifted, min_len=4)

                if fcorr > 0.5 or len(words) > 1:
                    shifted_interesting.append({
                        'n': n, 'offset': offset, 'shift': shift,
                        'freq_corr': fcorr, 'text': shifted[:40],
                        'words': [w for w, _ in words],
                    })

    if shifted_interesting:
        shifted_interesting.sort(key=lambda x: x['freq_corr'], reverse=True)
        print(f"  Found {len(shifted_interesting)} interesting Caesar-shifted decimations:")
        for entry in shifted_interesting[:10]:
            print(f"    N={entry['n']}, off={entry['offset']}, shift={entry['shift']}: "
                  f"corr={entry['freq_corr']:.3f}, words={entry['words']}, "
                  f"text={entry['text']}")
    else:
        print("  (No interesting Caesar-shifted decimations found)")

    results['shifted_decimations'] = shifted_interesting[:20] if shifted_interesting else []

    # ── Section 4: Grid-based reading orders ─────────────────────────────
    print("\n--- Section 4: Grid-based reading orders ---")
    print("  Read K4 as a grid of width W, then read columns/diagonals:")

    grid_results = []
    for width in range(5, 15):
        rows = (CT_LEN + width - 1) // width

        # Column-first reading
        for col in range(width):
            positions = [col + r * width for r in range(rows) if col + r * width < CT_LEN]
            text = ''.join(CT[i] for i in positions)
            ic = compute_ic(text)
            fcorr = frequency_correlation(text)
            if ic > 0.06 or fcorr > 0.3:
                grid_results.append({
                    'type': 'column', 'width': width, 'col': col,
                    'length': len(text), 'ic': ic, 'freq_corr': fcorr,
                    'text': text,
                })

        # Diagonal reading (main diagonals)
        for start_col in range(width):
            positions = [start_col + r * (width + 1) for r in range(rows)
                        if start_col + r * (width + 1) < CT_LEN]
            text = ''.join(CT[i] for i in positions)
            if len(text) >= 4:
                ic = compute_ic(text)
                if ic > 0.06:
                    grid_results.append({
                        'type': 'diagonal', 'width': width, 'start': start_col,
                        'length': len(text), 'ic': ic,
                        'text': text,
                    })

    if grid_results:
        grid_results.sort(key=lambda x: x['ic'], reverse=True)
        print(f"  Found {len(grid_results)} grid readings with IC > 0.06:")
        for entry in grid_results[:10]:
            print(f"    {entry['type']} w={entry['width']}: IC={entry['ic']:.4f}, "
                  f"text={entry['text'][:30]}")
    else:
        print("  (No interesting grid readings found)")

    results['grid_readings'] = grid_results[:15] if grid_results else []

    # ── Section 5: Reverse and other simple transforms ───────────────────
    print("\n--- Section 5: Simple transforms ---")

    transforms = {
        'reverse': CT[::-1],
        'odd_positions': ''.join(CT[i] for i in range(0, CT_LEN, 2)),
        'even_positions': ''.join(CT[i] for i in range(1, CT_LEN, 2)),
        'first_half': CT[:CT_LEN//2],
        'second_half': CT[CT_LEN//2:],
    }

    for name, text in transforms.items():
        ic = compute_ic(text)
        fcorr = frequency_correlation(text)
        words = find_english_words(text, min_len=3)
        print(f"  {name:20s}: IC={ic:.4f}, fcorr={fcorr:.3f}, "
              f"words={[w for w, _ in words]}")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")

    total_interesting = (len(interesting) + len(shifted_interesting) +
                        len(grid_results))

    if total_interesting == 0:
        verdict = "NO_NULL_CIPHER"
        print("  No evidence of null cipher or interval-readable message in K4.")
        print("  K4 does not contain hidden English text readable by decimation,")
        print("  grid reading, or simple transforms.")
    else:
        verdict = "POSSIBLE_SIGNAL"
        print(f"  Found {total_interesting} potentially interesting readings.")
        print("  Requires further investigation.")

    print(f"\n  Decimations with IC > 0.06: {k4_high_ic} (random mean: {mean_mc:.1f})")
    print(f"  Percentile: {pctile:.1f}%")
    print(f"  Runtime: {elapsed:.1f}s")
    print(f"\nRESULT: interesting={total_interesting} verdict={verdict}")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    output = {
        'experiment': 'E-FRAC-22',
        'description': 'Null cipher / interval reading analysis',
        'decimation_summary': results.get('decimation', {}),
        'mc_calibration': results.get('mc_calibration', {}),
        'shifted_decimations': results.get('shifted_decimations', []),
        'grid_readings': results.get('grid_readings', []),
        'verdict': verdict,
        'runtime': elapsed,
    }
    with open("results/frac/e_frac_22_null_cipher_intervals.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"  Results written to results/frac/e_frac_22_null_cipher_intervals.json")


if __name__ == "__main__":
    main()
