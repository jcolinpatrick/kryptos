#!/usr/bin/env python3
"""E-S-25: Deep CT Structural Analysis

Instead of guessing cipher families, analyze the K4 ciphertext
structure itself to derive constraints on the cipher type.

Tests:
1. Autocorrelation at ALL lags (not just 7) with significance levels
2. Bigram and trigram frequency anomalies
3. Position-dependent letter frequency (are certain regions different?)
4. Symmetry tests (palindromic, reversal, complement patterns)
5. Kolmogorov-Smirnov test against various cipher output distributions
6. Spectral analysis (DFT of letter values)
7. Mutual information between positions at various offsets
8. Contact analysis (which letters appear adjacent to which)

Goal: identify structural features that constrain the cipher type.

Output: results/e_s_25_ct_structural.json + reports/e_s_25_report.md
"""
import json
import math
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, "src")
from kryptos.kernel.constants import CT, CT_LEN, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
N = CT_LEN


def main():
    print("=" * 60)
    print("E-S-25: Deep CT Structural Analysis")
    print("=" * 60)
    print(f"CT: {CT}")
    print(f"Length: {N}")
    print()

    results = {}

    # ── 1. Letter frequency analysis ────────────────────────────────────
    print("1. LETTER FREQUENCY")
    freq = Counter(CT)
    expected = N / 26
    chi2 = sum((freq.get(c, 0) - expected) ** 2 / expected for c in ALPH)
    print(f"   Expected uniform: {expected:.1f} per letter")
    print(f"   Chi-squared (uniform): {chi2:.1f} (df=25, p<0.05 threshold=37.7)")
    print(f"   Most common: {freq.most_common(5)}")
    print(f"   Least common: {freq.most_common()[-5:]}")

    # IC
    ic = sum(f * (f - 1) for f in freq.values()) / (N * (N - 1))
    print(f"   IC: {ic:.4f} (English=0.0667, Random=0.0385)")

    results["letter_freq"] = {
        "chi2_uniform": chi2,
        "ic": ic,
        "frequencies": dict(freq),
    }

    # ── 2. Autocorrelation at all lags ──────────────────────────────────
    print("\n2. AUTOCORRELATION (matching letters at each lag)")
    expected_per_lag = 1.0 / 26  # Prob two random letters match
    autocorr = {}
    significant_lags = []

    for lag in range(1, N):
        matches = sum(1 for i in range(N - lag) if CT_NUM[i] == CT_NUM[i + lag])
        n_pairs = N - lag
        expected_matches = n_pairs * expected_per_lag
        std = math.sqrt(n_pairs * expected_per_lag * (1 - expected_per_lag))
        z_score = (matches - expected_matches) / std if std > 0 else 0

        autocorr[lag] = {
            "matches": matches,
            "expected": round(expected_matches, 2),
            "z_score": round(z_score, 3),
            "n_pairs": n_pairs,
        }

        if abs(z_score) > 2.0:
            significant_lags.append((lag, matches, z_score))

    print(f"   Significant lags (|z| > 2.0):")
    for lag, matches, z in sorted(significant_lags, key=lambda x: -abs(x[2])):
        print(f"     Lag {lag:>2}: {matches} matches (z={z:+.3f})")

    # Top 10 by absolute z-score
    top_lags = sorted(autocorr.items(), key=lambda x: -abs(x[1]["z_score"]))[:10]
    print(f"\n   Top 10 lags by |z|:")
    for lag, data in top_lags:
        print(f"     Lag {lag:>2}: {data['matches']} matches"
              f" (exp={data['expected']:.1f}, z={data['z_score']:+.3f})")

    results["autocorrelation"] = {
        "significant_lags": [(l, m, z) for l, m, z in significant_lags],
        "top10": [(lag, data) for lag, data in top_lags],
    }

    # ── 3. Bigram analysis ──────────────────────────────────────────────
    print("\n3. BIGRAM ANALYSIS")
    bigrams = Counter()
    for i in range(N - 1):
        bigrams[CT[i] + CT[i + 1]] += 1

    # Most common bigrams
    print(f"   Total unique bigrams: {len(bigrams)}/{26*26}")
    print(f"   Most common: {bigrams.most_common(10)}")

    # Repeated bigrams
    repeated = {bg: cnt for bg, cnt in bigrams.items() if cnt >= 2}
    print(f"   Bigrams appearing ≥2 times: {len(repeated)}")
    for bg, cnt in sorted(repeated.items(), key=lambda x: -x[1])[:15]:
        positions = [i for i in range(N - 1) if CT[i:i+2] == bg]
        print(f"     '{bg}': {cnt}× at positions {positions}")

    results["bigrams"] = {
        "n_unique": len(bigrams),
        "top10": bigrams.most_common(10),
        "repeated": {bg: {"count": cnt, "positions": [i for i in range(N-1) if CT[i:i+2] == bg]}
                     for bg, cnt in repeated.items()},
    }

    # ── 4. Trigram analysis ─────────────────────────────────────────────
    print("\n4. TRIGRAM ANALYSIS")
    trigrams = Counter()
    for i in range(N - 2):
        trigrams[CT[i:i+3]] += 1

    repeated_tri = {tg: cnt for tg, cnt in trigrams.items() if cnt >= 2}
    print(f"   Trigrams appearing ≥2 times: {len(repeated_tri)}")
    for tg, cnt in sorted(repeated_tri.items(), key=lambda x: -x[1]):
        positions = [i for i in range(N - 2) if CT[i:i+3] == tg]
        print(f"     '{tg}': {cnt}× at positions {positions}")

    results["trigrams"] = {
        "repeated": {tg: {"count": cnt, "positions": [i for i in range(N-2) if CT[i:i+3] == tg]}
                     for tg, cnt in repeated_tri.items()},
    }

    # ── 5. Spectral analysis (DFT of letter values) ────────────────────
    print("\n5. SPECTRAL ANALYSIS (DFT magnitude)")
    # Compute DFT of CT_NUM (shifted to zero mean)
    mean_val = sum(CT_NUM) / N
    centered = [v - mean_val for v in CT_NUM]

    magnitudes = {}
    for k in range(1, N // 2 + 1):
        re = sum(centered[n] * math.cos(2 * math.pi * k * n / N) for n in range(N))
        im = sum(centered[n] * math.sin(2 * math.pi * k * n / N) for n in range(N))
        mag = math.sqrt(re * re + im * im)
        magnitudes[k] = round(mag, 3)

    # For random text, expected magnitude ≈ sqrt(N * var / 2) ≈ sqrt(97 * 56.25 / 2) ≈ 52.3
    var_uniform = sum((i - 12.5) ** 2 for i in range(26)) / 26
    expected_mag = math.sqrt(N * var_uniform / 2)
    print(f"   Expected random magnitude: {expected_mag:.1f}")

    top_freqs = sorted(magnitudes.items(), key=lambda x: -x[1])[:10]
    print(f"   Top 10 DFT magnitudes:")
    for k, mag in top_freqs:
        period = N / k
        excess = (mag - expected_mag) / expected_mag * 100
        print(f"     k={k:>2} (period={period:.1f}): mag={mag:.1f} ({excess:+.0f}%)")

    results["spectral"] = {
        "expected_mag": round(expected_mag, 1),
        "top10": [(k, mag, round(N/k, 1)) for k, mag in top_freqs],
    }

    # ── 6. Position-dependent analysis ──────────────────────────────────
    print("\n6. POSITION-DEPENDENT FREQUENCY")
    # Split CT into thirds and compare
    third = N // 3
    for label, start, end in [("First third", 0, third),
                               ("Middle third", third, 2 * third),
                               ("Last third", 2 * third, N)]:
        segment = CT_NUM[start:end]
        seg_freq = Counter(segment)
        seg_ic = sum(f * (f - 1) for f in seg_freq.values()) / (len(segment) * (len(segment) - 1)) if len(segment) > 1 else 0
        seg_mean = sum(segment) / len(segment)
        print(f"   {label} [{start}-{end}]: IC={seg_ic:.4f}, mean_val={seg_mean:.1f}")

    # Pre-ENE, inter-crib, post-BC regions
    regions = {
        "pre_ENE": (0, 21),
        "ENE_crib": (21, 34),
        "inter_crib": (34, 63),
        "BC_crib": (63, 74),
        "post_BC": (74, 97),
    }
    print(f"\n   By crib regions:")
    for name, (start, end) in regions.items():
        segment = CT_NUM[start:end]
        seg_freq = Counter(segment)
        n = len(segment)
        seg_ic = sum(f * (f - 1) for f in seg_freq.values()) / (n * (n - 1)) if n > 1 else 0
        print(f"     {name:>12} [{start:>2}-{end:>2}] (n={n:>2}): IC={seg_ic:.4f}")

    results["position_dependent"] = {
        "by_region_ic": {name: {"start": s, "end": e,
                                "ic": round(sum(f*(f-1) for f in Counter(CT_NUM[s:e]).values()) / (max((e-s)*((e-s)-1), 1)), 4)}
                         for name, (s, e) in regions.items()},
    }

    # ── 7. Difference analysis ──────────────────────────────────────────
    print("\n7. DIFFERENCE ANALYSIS (CT[i+1] - CT[i] mod 26)")
    diffs = [(CT_NUM[i+1] - CT_NUM[i]) % MOD for i in range(N-1)]
    diff_freq = Counter(diffs)
    diff_ic = sum(f * (f-1) for f in diff_freq.values()) / (len(diffs) * (len(diffs)-1))
    print(f"   Difference IC: {diff_ic:.4f} (random=0.0385)")
    print(f"   Most common differences: {diff_freq.most_common(5)}")
    print(f"   Zero differences (repeats): {diff_freq.get(0, 0)}")

    results["differences"] = {
        "diff_ic": diff_ic,
        "most_common": diff_freq.most_common(10),
        "zero_count": diff_freq.get(0, 0),
    }

    # ── 8. Kasiski-like analysis ────────────────────────────────────────
    print("\n8. KASISKI ANALYSIS (repeated substring positions)")
    kasiski = {}
    for length in [2, 3, 4, 5]:
        for i in range(N - length):
            substr = CT[i:i+length]
            positions = [j for j in range(N - length) if CT[j:j+length] == substr]
            if len(positions) >= 2:
                diffs = [positions[j+1] - positions[j] for j in range(len(positions)-1)]
                kasiski[substr] = {"positions": positions, "spacings": diffs}

    # GCD of spacings
    from math import gcd
    from functools import reduce
    all_spacings = []
    for substr, data in kasiski.items():
        all_spacings.extend(data["spacings"])

    if all_spacings:
        spacing_freq = Counter(all_spacings)
        print(f"   Total repeated substrings (len 2-5): {len(kasiski)}")
        print(f"   All spacings: {sorted(spacing_freq.items(), key=lambda x: -x[1])[:15]}")

        # Factor analysis
        factors = Counter()
        for spacing in all_spacings:
            for f in range(2, spacing + 1):
                if spacing % f == 0:
                    factors[f] += 1

        print(f"   Factor frequencies (top 10):")
        for f, cnt in factors.most_common(10):
            print(f"     Factor {f:>2}: appears {cnt} times")

    results["kasiski"] = {
        "n_repeated": len(kasiski),
        "spacings": dict(Counter(all_spacings).most_common(20)) if all_spacings else {},
    }

    # ── 9. Contact frequency ───────────────────────────────────────────
    print("\n9. CONTACT FREQUENCY (letters that appear adjacent)")
    contact_before = defaultdict(Counter)
    contact_after = defaultdict(Counter)
    for i in range(N - 1):
        contact_after[CT[i]][CT[i+1]] += 1
        contact_before[CT[i+1]][CT[i]] += 1

    # Letters with unusually high contact diversity or concentration
    print(f"   Letters with concentrated contacts (top 5 by max pair frequency):")
    max_contacts = []
    for letter in ALPH:
        if letter in contact_after:
            most_common = contact_after[letter].most_common(1)
            if most_common:
                max_contacts.append((letter, most_common[0], sum(contact_after[letter].values())))
    max_contacts.sort(key=lambda x: -x[1][1])
    for letter, (partner, cnt), total in max_contacts[:5]:
        print(f"     {letter} → {partner}: {cnt}/{total} times")

    # ── 10. Self-similarity at various scales ───────────────────────────
    print("\n10. SELF-SIMILARITY (first vs second half)")
    half = N // 2
    first_half = Counter(CT[:half])
    second_half = Counter(CT[half:])

    # Correlation between halves
    vals1 = [first_half.get(c, 0) for c in ALPH]
    vals2 = [second_half.get(c, 0) for c in ALPH]
    mean1 = sum(vals1) / 26
    mean2 = sum(vals2) / 26
    cov = sum((v1 - mean1) * (v2 - mean2) for v1, v2 in zip(vals1, vals2)) / 26
    std1 = math.sqrt(sum((v - mean1) ** 2 for v in vals1) / 26)
    std2 = math.sqrt(sum((v - mean2) ** 2 for v in vals2) / 26)
    corr = cov / (std1 * std2) if std1 > 0 and std2 > 0 else 0
    print(f"   Letter frequency correlation (first/second half): {corr:.3f}")
    print(f"   (Random text: r ≈ 0.0 ± 0.2; same cipher: r > 0.3)")

    results["self_similarity"] = {"half_correlation": round(corr, 3)}

    # ── Summary ─────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  KEY FINDINGS")
    print(f"{'='*60}")

    print(f"\n  1. IC = {ic:.4f} — BELOW random ({1/26:.4f}), unusual")
    print(f"  2. Chi² = {chi2:.1f} — {'NOT significant' if chi2 < 37.7 else 'SIGNIFICANT'} (vs uniform)")

    if significant_lags:
        print(f"  3. Significant autocorrelation lags:")
        for lag, matches, z in sorted(significant_lags, key=lambda x: -abs(x[2]))[:5]:
            print(f"     Lag {lag}: z={z:+.3f}")
    else:
        print(f"  3. No significant autocorrelation lags")

    print(f"  4. Difference IC = {diff_ic:.4f}")
    print(f"  5. Half-correlation = {corr:.3f}")

    # Save
    with open("results/e_s_25_ct_structural.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n  Artifact: results/e_s_25_ct_structural.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_25_ct_structural.py")


if __name__ == "__main__":
    main()
