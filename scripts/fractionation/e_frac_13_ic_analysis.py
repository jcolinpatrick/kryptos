#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-13: IC Statistical Analysis — Is K4's below-random IC significant?

Questions:
1. Is K4's IC = 0.0361 statistically unusual for random text of length 97?
2. Does the pre-ENE segment (pos 0-20, IC=0.067) have significantly different IC?
3. What IC does Bifid 6×6 produce for 97-char texts at various periods?
4. What IC do other cipher families produce?

This constrains which cipher families are compatible with K4's IC signature.
"""

import json
import os
import random
import time
from collections import Counter
from pathlib import Path

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD, CRIB_DICT, CRIB_ENTRIES,
    IC_K4, IC_RANDOM, IC_ENGLISH, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)


def compute_ic(text: str) -> float:
    """Index of coincidence for a string of uppercase letters."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def random_text(length: int) -> str:
    """Uniform random uppercase text."""
    return ''.join(random.choice(ALPH) for _ in range(length))


def vigenere_encrypt(pt: str, key: list[int]) -> str:
    """Vigenere encrypt plaintext with a repeating key."""
    ct = []
    for i, ch in enumerate(pt):
        p = ord(ch) - ord('A')
        k = key[i % len(key)]
        ct.append(ALPH[(p + k) % 26])
    return ''.join(ct)


def beaufort_encrypt(pt: str, key: list[int]) -> str:
    """Beaufort encrypt: CT = (K - PT) mod 26."""
    ct = []
    for i, ch in enumerate(pt):
        p = ord(ch) - ord('A')
        k = key[i % len(key)]
        ct.append(ALPH[(k - p) % 26])
    return ''.join(ct)


def make_polybius_6x6(letters: str) -> tuple[dict, list]:
    """Create a 6×6 Polybius square from 26 letters (placed in first 26 of 36 cells).

    Returns: (letter→(row,col) mapping, (row,col)→letter list)
    """
    grid = {}
    reverse = [''] * 36
    for idx, ch in enumerate(letters):
        r, c = divmod(idx, 6)
        grid[ch] = (r, c)
        reverse[r * 6 + c] = ch
    return grid, reverse


def bifid_encrypt(pt: str, polybius: dict, reverse: list, period: int) -> str:
    """Bifid encryption with given Polybius square and period."""
    ct_chars = []
    # Process in blocks of `period`
    for start in range(0, len(pt), period):
        block = pt[start:start + period]
        rows = []
        cols = []
        for ch in block:
            r, c = polybius[ch]
            rows.append(r)
            cols.append(c)
        # Concatenate rows then cols
        combined = rows + cols
        # Read off pairs
        for j in range(0, len(combined), 2):
            r2 = combined[j]
            c2 = combined[j + 1] if j + 1 < len(combined) else 0
            cell = r2 * 6 + c2
            letter = reverse[cell]
            if letter:
                ct_chars.append(letter)
            else:
                # Empty cell — use fallback
                ct_chars.append('A')
    return ''.join(ct_chars)


def generate_english_like(length: int) -> str:
    """Generate pseudo-English text (letter frequencies matching English)."""
    # English letter frequencies (approximate)
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


def main():
    start_time = time.time()
    random.seed(42)
    results = {}

    print("=" * 70)
    print("E-FRAC-13: IC Statistical Analysis")
    print("=" * 70)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 1: K4's IC in context — is 0.0361 unusual for random text?
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 1: Random IC distribution for N=97 ---")
    N_SAMPLES = 200_000
    random_ics = []
    for _ in range(N_SAMPLES):
        t = random_text(CT_LEN)
        random_ics.append(compute_ic(t))

    random_ics.sort()
    mean_ic = sum(random_ics) / len(random_ics)
    std_ic = (sum((x - mean_ic) ** 2 for x in random_ics) / len(random_ics)) ** 0.5

    # Percentile of K4's IC in the random distribution
    k4_rank = sum(1 for x in random_ics if x <= IC_K4) / len(random_ics)

    # How many standard deviations below mean?
    z_score = (IC_K4 - mean_ic) / std_ic if std_ic > 0 else 0

    print(f"  Random text IC (N={N_SAMPLES}, length=97):")
    print(f"    Mean:   {mean_ic:.6f}")
    print(f"    Std:    {std_ic:.6f}")
    print(f"    Min:    {min(random_ics):.6f}")
    print(f"    Max:    {max(random_ics):.6f}")
    print(f"    5th %:  {random_ics[int(0.05 * N_SAMPLES)]:.6f}")
    print(f"    95th %: {random_ics[int(0.95 * N_SAMPLES)]:.6f}")
    print(f"  K4 IC = {IC_K4:.4f}")
    print(f"    Percentile: {k4_rank * 100:.2f}%")
    print(f"    Z-score: {z_score:.3f}")

    if k4_rank < 0.01:
        print(f"    *** K4's IC is SIGNIFICANTLY below random (p < 0.01) ***")
        ic_significant = True
    elif k4_rank < 0.05:
        print(f"    ** K4's IC is marginally below random (p < 0.05) **")
        ic_significant = True
    else:
        print(f"    K4's IC is NOT significantly different from random (p = {k4_rank:.3f})")
        ic_significant = False

    results['part1_random_ic'] = {
        'n_samples': N_SAMPLES,
        'mean': mean_ic,
        'std': std_ic,
        'min': min(random_ics),
        'max': max(random_ics),
        'p5': random_ics[int(0.05 * N_SAMPLES)],
        'p95': random_ics[int(0.95 * N_SAMPLES)],
        'k4_ic': IC_K4,
        'k4_percentile': k4_rank,
        'k4_z_score': z_score,
        'significant': ic_significant,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 2: Verify K4's IC and segment ICs directly
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 2: K4 segment IC analysis ---")

    segments = {
        'full': (CT, 0, CT_LEN),
        'pre_ENE': (CT[0:21], 0, 21),
        'ENE_crib': (CT[21:34], 21, 34),
        'mid_gap': (CT[34:63], 34, 63),
        'BC_crib': (CT[63:74], 63, 74),
        'post_BC': (CT[74:97], 74, 97),
    }

    seg_results = {}
    for name, (seg, s, e) in segments.items():
        seg_ic = compute_ic(seg)
        n = len(seg)

        # Monte Carlo: what's the random IC distribution for this length?
        seg_random_ics = [compute_ic(random_text(n)) for _ in range(50_000)]
        seg_random_ics.sort()
        seg_mean = sum(seg_random_ics) / len(seg_random_ics)
        seg_std = (sum((x - seg_mean) ** 2 for x in seg_random_ics) / len(seg_random_ics)) ** 0.5
        seg_pctile = sum(1 for x in seg_random_ics if x <= seg_ic) / len(seg_random_ics)

        print(f"  {name} (pos {s}-{e-1}, n={n}): IC = {seg_ic:.4f}")
        print(f"    Random mean = {seg_mean:.4f}, std = {seg_std:.4f}")
        print(f"    Percentile in random: {seg_pctile * 100:.1f}%")

        seg_results[name] = {
            'start': s, 'end': e, 'length': n,
            'ic': seg_ic,
            'random_mean': seg_mean, 'random_std': seg_std,
            'percentile': seg_pctile,
        }

    results['part2_segments'] = seg_results

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 3: IC under periodic Vigenere/Beaufort (various periods)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 3: IC under periodic Vigenere/Beaufort ---")
    N_VIG = 50_000

    vig_results = {}
    for period in [1, 2, 3, 5, 7, 10, 15, 20, 50, 97]:
        ics = []
        for _ in range(N_VIG):
            pt = generate_english_like(CT_LEN)
            key = [random.randint(0, 25) for _ in range(period)]
            ct = vigenere_encrypt(pt, key)
            ics.append(compute_ic(ct))
        ics.sort()
        m = sum(ics) / len(ics)
        s = (sum((x - m) ** 2 for x in ics) / len(ics)) ** 0.5
        pctile = sum(1 for x in ics if x <= IC_K4) / len(ics)
        print(f"  Period {period:3d}: mean IC = {m:.5f}, std = {s:.5f}, K4 pctile = {pctile * 100:.1f}%")
        vig_results[str(period)] = {
            'mean': m, 'std': s, 'k4_percentile': pctile,
            'p5': ics[int(0.05 * N_VIG)], 'p95': ics[int(0.95 * N_VIG)],
        }

    results['part3_vigenere_ic'] = vig_results

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 4: IC under Bifid 6×6 (various periods)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 4: IC under Bifid 6×6 ---")
    N_BIF = 20_000

    bifid_results = {}
    for period in [2, 3, 4, 5, 7, 10, 15, 20, 48, 97]:
        ics = []
        for _ in range(N_BIF):
            # Random English-like plaintext
            pt = generate_english_like(CT_LEN)
            # Random Polybius square: shuffle 26 letters into first 26 of 36 cells
            letters = list(ALPH)
            random.shuffle(letters)
            polybius, reverse = make_polybius_6x6(''.join(letters))
            ct = bifid_encrypt(pt, polybius, reverse, period)
            if len(ct) >= CT_LEN:
                ics.append(compute_ic(ct[:CT_LEN]))
        if ics:
            ics.sort()
            m = sum(ics) / len(ics)
            s = (sum((x - m) ** 2 for x in ics) / len(ics)) ** 0.5
            pctile = sum(1 for x in ics if x <= IC_K4) / len(ics)
            print(f"  Bifid p={period:3d}: mean IC = {m:.5f}, std = {s:.5f}, K4 pctile = {pctile * 100:.1f}%")
            bifid_results[str(period)] = {
                'mean': m, 'std': s, 'k4_percentile': pctile,
                'n': len(ics),
            }
        else:
            print(f"  Bifid p={period}: no valid outputs")

    results['part4_bifid_ic'] = bifid_results

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 5: IC under Bifid 5×5 (for comparison, using I/J merge)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 5: IC under Bifid 5×5 (I/J merged) ---")
    # Note: Bifid 5×5 is structurally impossible for K4 (CT has all 26 letters)
    # but we compute its IC signature for comparison

    def make_polybius_5x5(letters25: str) -> tuple[dict, list]:
        grid = {}
        reverse = [''] * 25
        for idx, ch in enumerate(letters25):
            r, c = divmod(idx, 5)
            grid[ch] = (r, c)
            reverse[r * 5 + c] = ch
        return grid, reverse

    def bifid5_encrypt(pt: str, polybius: dict, reverse: list, period: int) -> str:
        ct_chars = []
        for start in range(0, len(pt), period):
            block = pt[start:start + period]
            rows, cols = [], []
            for ch in block:
                ch2 = ch if ch != 'J' else 'I'  # I/J merge
                if ch2 in polybius:
                    r, c = polybius[ch2]
                    rows.append(r)
                    cols.append(c)
            combined = rows + cols
            for j in range(0, len(combined), 2):
                r2 = combined[j]
                c2 = combined[j + 1] if j + 1 < len(combined) else 0
                ct_chars.append(reverse[r2 * 5 + c2])
        return ''.join(ct_chars)

    N_BIF5 = 20_000
    bifid5_results = {}
    for period in [2, 3, 5, 7, 10, 97]:
        ics = []
        for _ in range(N_BIF5):
            pt = generate_english_like(CT_LEN)
            # 25-letter alphabet (no J)
            letters25 = [c for c in ALPH if c != 'J']
            random.shuffle(letters25)
            polybius, reverse = make_polybius_5x5(''.join(letters25))
            ct = bifid5_encrypt(pt, polybius, reverse, period)
            if len(ct) >= CT_LEN:
                ics.append(compute_ic(ct[:CT_LEN]))
        if ics:
            ics.sort()
            m = sum(ics) / len(ics)
            s = (sum((x - m) ** 2 for x in ics) / len(ics)) ** 0.5
            pctile = sum(1 for x in ics if x <= IC_K4) / len(ics)
            print(f"  Bifid5 p={period:3d}: mean IC = {m:.5f}, std = {s:.5f}, K4 pctile = {pctile * 100:.1f}%")
            bifid5_results[str(period)] = {
                'mean': m, 'std': s, 'k4_percentile': pctile, 'n': len(ics),
            }

    results['part5_bifid5_ic'] = bifid5_results

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 6: IC under progressive key models
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 6: IC under progressive key / running key ---")
    N_PROG = 50_000

    prog_results = {}
    for model_name, encrypt_fn in [('progressive_vig', vigenere_encrypt),
                                     ('progressive_beau', beaufort_encrypt)]:
        ics = []
        for _ in range(N_PROG):
            pt = generate_english_like(CT_LEN)
            # Running key: random key of full length (non-periodic)
            key = [random.randint(0, 25) for _ in range(CT_LEN)]
            ct = encrypt_fn(pt, key)
            ics.append(compute_ic(ct))
        ics.sort()
        m = sum(ics) / len(ics)
        s = (sum((x - m) ** 2 for x in ics) / len(ics)) ** 0.5
        pctile = sum(1 for x in ics if x <= IC_K4) / len(ics)
        print(f"  {model_name}: mean IC = {m:.5f}, std = {s:.5f}, K4 pctile = {pctile * 100:.1f}%")
        prog_results[model_name] = {'mean': m, 'std': s, 'k4_percentile': pctile}

    results['part6_progressive_ic'] = prog_results

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 7: IC under transposition (preserves IC exactly)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 7: IC under transposition (verification) ---")
    # Transposition preserves letter frequencies, so IC is unchanged.
    # Verify: random English text → transpose → check IC unchanged
    unchanged_count = 0
    N_CHECK = 10_000
    for _ in range(N_CHECK):
        pt = generate_english_like(CT_LEN)
        perm = list(range(CT_LEN))
        random.shuffle(perm)
        transposed = ''.join(pt[perm[i]] for i in range(CT_LEN))
        ic_orig = compute_ic(pt)
        ic_trans = compute_ic(transposed)
        if abs(ic_orig - ic_trans) < 1e-12:
            unchanged_count += 1

    pct = unchanged_count / N_CHECK * 100
    print(f"  IC preserved exactly: {unchanged_count}/{N_CHECK} ({pct:.1f}%)")
    results['part7_transposition_ic'] = {'preserved_pct': pct, 'n': N_CHECK}

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 8: Combined model — transposition + Bifid
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 8: IC under transposition + Bifid 6×6 ---")
    # Since transposition preserves IC, transposition + Bifid gives same IC as Bifid alone.
    # But let's verify: transpose English text, then Bifid, measure IC.
    N_COMBO = 10_000
    combo_results = {}
    for period in [3, 5, 7, 10]:
        ics = []
        for _ in range(N_COMBO):
            pt = generate_english_like(CT_LEN)
            perm = list(range(CT_LEN))
            random.shuffle(perm)
            transposed = ''.join(pt[perm[i]] for i in range(CT_LEN))
            letters = list(ALPH)
            random.shuffle(letters)
            polybius, reverse = make_polybius_6x6(''.join(letters))
            ct = bifid_encrypt(transposed, polybius, reverse, period)
            if len(ct) >= CT_LEN:
                ics.append(compute_ic(ct[:CT_LEN]))
        if ics:
            m = sum(ics) / len(ics)
            s = (sum((x - m) ** 2 for x in ics) / len(ics)) ** 0.5
            pctile = sum(1 for x in ics if x <= IC_K4) / len(ics)
            print(f"  Trans+Bifid p={period:3d}: mean IC = {m:.5f} (cf Bifid alone: {bifid_results.get(str(period), {}).get('mean', 'N/A')})")
            combo_results[str(period)] = {'mean': m, 'std': s, 'k4_percentile': pctile}

    results['part8_trans_bifid_ic'] = combo_results

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 9: What letter frequency profile produces IC ≈ 0.036?
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 9: K4's actual letter frequencies ---")
    k4_counts = Counter(CT)
    total = sum(k4_counts.values())
    print(f"  Total: {total}")
    print(f"  Unique letters: {len(k4_counts)}")

    # Actual IC computation
    actual_ic = sum(c * (c - 1) for c in k4_counts.values()) / (total * (total - 1))
    print(f"  Computed IC: {actual_ic:.6f} (constants say: {IC_K4})")

    # Chi-squared vs uniform
    expected = total / 26
    chi2 = sum((k4_counts.get(c, 0) - expected) ** 2 / expected for c in ALPH)
    # Chi-squared with 25 df, critical values: 5% = 37.65, 1% = 44.31
    print(f"  Chi-squared vs uniform: {chi2:.2f} (df=25, 5% critical = 37.65)")
    if chi2 < 37.65:
        print(f"    NOT significantly different from uniform at 5% level")
    else:
        print(f"    *** Significantly different from uniform ***")

    # Sort by frequency
    sorted_freqs = sorted(k4_counts.items(), key=lambda x: -x[1])
    print(f"  Top 5 letters: {', '.join(f'{ch}={n}' for ch, n in sorted_freqs[:5])}")
    print(f"  Bottom 5: {', '.join(f'{ch}={n}' for ch, n in sorted_freqs[-5:])}")

    results['part9_k4_freq'] = {
        'actual_ic': actual_ic,
        'chi2_vs_uniform': chi2,
        'uniform_rejected_5pct': chi2 >= 37.65,
        'letter_counts': dict(k4_counts),
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Summary
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    runtime = time.time() - start_time

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(f"\n1. K4 IC = {IC_K4:.4f}")
    print(f"   Random mean = {mean_ic:.4f}, std = {std_ic:.4f}")
    print(f"   K4 percentile in random: {k4_rank * 100:.1f}%")
    print(f"   Z-score: {z_score:.3f}")
    if not ic_significant:
        print("   → K4's IC is NOT unusually low. It's within normal random variation.")
        print("   → Below-random IC is NOT evidence for fractionation or any specific cipher.")
    else:
        print("   → K4's IC IS unusually low, suggesting non-random structure.")

    # Cipher family compatibility summary
    print(f"\n2. Cipher family IC compatibility with K4:")
    for family, data in [
        ("Periodic Vig p=1 (monoalph)", vig_results.get('1', {})),
        ("Periodic Vig p=5", vig_results.get('5', {})),
        ("Periodic Vig p=97 (full)", vig_results.get('97', {})),
        ("Bifid 6×6 p=5", bifid_results.get('5', {})),
        ("Bifid 6×6 p=97", bifid_results.get('97', {})),
        ("Running key Vig", prog_results.get('progressive_vig', {})),
    ]:
        if data:
            pct = data.get('k4_percentile', 0) * 100
            print(f"   {family:30s}: K4 at {pct:5.1f}th percentile")

    print(f"\n3. K4 letter distribution vs uniform: chi2 = {chi2:.2f}")
    if chi2 < 37.65:
        print("   → K4 looks UNIFORM — consistent with long-period polyalphabetic or running key")

    print(f"\nRuntime: {runtime:.1f}s")
    print(f"RESULT: IC analysis complete. K4 IC percentile in random = {k4_rank*100:.1f}%")

    results['summary'] = {
        'k4_ic': IC_K4,
        'k4_percentile_in_random': k4_rank,
        'k4_z_score': z_score,
        'ic_significant': ic_significant,
        'chi2_vs_uniform': chi2,
        'uniform_rejected': chi2 >= 37.65,
        'runtime': runtime,
    }

    # Save results
    out_dir = Path("results/frac")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "e_frac_13_ic_analysis.json"
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
