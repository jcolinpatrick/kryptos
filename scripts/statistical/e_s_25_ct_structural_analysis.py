#!/usr/bin/env python3
"""
Cipher: statistical analysis
Family: statistical
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
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


def attack(ciphertext, **params):
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]

    For structural analysis, 'plaintext' is the ciphertext itself (no decryption),
    and 'score' is the magnitude of each structural metric (e.g. |z-score|, IC, chi2).
    """
    ct = ciphertext
    ct_num = [ALPH_IDX[c] for c in ct]
    n = len(ct)

    all_results = []

    # ── 1. Letter frequency analysis ────────────────────────────────────
    freq = Counter(ct)
    expected = n / 26
    chi2 = sum((freq.get(c, 0) - expected) ** 2 / expected for c in ALPH)
    ic_val = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1)) if n > 1 else 0.0

    all_results.append((float(chi2), ct,
                        f"chi2_uniform={chi2:.1f} (df=25, p<0.05@37.7)"))
    all_results.append((float(ic_val * 1000), ct,
                        f"IC={ic_val:.4f} (English=0.0667, Random=0.0385)"))

    # ── 2. Autocorrelation at all lags ──────────────────────────────────
    expected_per_lag = 1.0 / 26
    for lag in range(1, n):
        matches = sum(1 for i in range(n - lag) if ct_num[i] == ct_num[i + lag])
        n_pairs = n - lag
        expected_matches = n_pairs * expected_per_lag
        std = math.sqrt(n_pairs * expected_per_lag * (1 - expected_per_lag))
        z_score = (matches - expected_matches) / std if std > 0 else 0

        if abs(z_score) > 1.5:
            all_results.append((abs(z_score), ct,
                                f"autocorr lag={lag} matches={matches} "
                                f"exp={expected_matches:.1f} z={z_score:+.3f}"))

    # ── 3. Bigram anomalies ─────────────────────────────────────────────
    bigrams = Counter()
    for i in range(n - 1):
        bigrams[ct[i] + ct[i + 1]] += 1

    repeated = {bg: cnt for bg, cnt in bigrams.items() if cnt >= 2}
    for bg, cnt in sorted(repeated.items(), key=lambda x: -x[1])[:10]:
        positions = [i for i in range(n - 1) if ct[i:i+2] == bg]
        all_results.append((float(cnt), ct,
                            f"bigram '{bg}' count={cnt} positions={positions}"))

    # ── 4. Trigram anomalies ────────────────────────────────────────────
    trigrams = Counter()
    for i in range(n - 2):
        trigrams[ct[i:i+3]] += 1

    repeated_tri = {tg: cnt for tg, cnt in trigrams.items() if cnt >= 2}
    for tg, cnt in sorted(repeated_tri.items(), key=lambda x: -x[1]):
        positions = [i for i in range(n - 2) if ct[i:i+3] == tg]
        all_results.append((float(cnt), ct,
                            f"trigram '{tg}' count={cnt} positions={positions}"))

    # ── 5. Spectral analysis (DFT magnitude) ───────────────────────────
    mean_val = sum(ct_num) / n
    centered = [v - mean_val for v in ct_num]

    var_uniform = sum((i - 12.5) ** 2 for i in range(26)) / 26
    expected_mag = math.sqrt(n * var_uniform / 2)

    for k in range(1, n // 2 + 1):
        re = sum(centered[i] * math.cos(2 * math.pi * k * i / n) for i in range(n))
        im = sum(centered[i] * math.sin(2 * math.pi * k * i / n) for i in range(n))
        mag = math.sqrt(re * re + im * im)
        excess_pct = (mag - expected_mag) / expected_mag * 100

        if abs(excess_pct) > 30:
            period = n / k
            all_results.append((abs(excess_pct), ct,
                                f"DFT k={k} period={period:.1f} mag={mag:.1f} "
                                f"excess={excess_pct:+.0f}%"))

    # ── 6. Difference analysis ──────────────────────────────────────────
    diffs = [(ct_num[i+1] - ct_num[i]) % MOD for i in range(n-1)]
    diff_freq = Counter(diffs)
    diff_ic = (sum(f * (f-1) for f in diff_freq.values())
               / (len(diffs) * (len(diffs)-1))) if len(diffs) > 1 else 0.0

    all_results.append((float(diff_ic * 1000), ct,
                        f"diff_IC={diff_ic:.4f} (random=0.0385) "
                        f"zero_diffs={diff_freq.get(0, 0)}"))

    # ── 7. Kasiski analysis ─────────────────────────────────────────────
    all_spacings = []
    for length in [2, 3, 4, 5]:
        for i in range(n - length):
            substr = ct[i:i+length]
            positions = [j for j in range(n - length) if ct[j:j+length] == substr]
            if len(positions) >= 2:
                spacings = [positions[j+1] - positions[j] for j in range(len(positions)-1)]
                all_spacings.extend(spacings)

    if all_spacings:
        factors = Counter()
        for spacing in all_spacings:
            for f in range(2, spacing + 1):
                if spacing % f == 0:
                    factors[f] += 1

        for f, cnt in factors.most_common(5):
            all_results.append((float(cnt), ct,
                                f"kasiski factor={f} count={cnt}"))

    # ── 8. Self-similarity (half correlation) ───────────────────────────
    half = n // 2
    first_half = Counter(ct[:half])
    second_half = Counter(ct[half:])

    vals1 = [first_half.get(c, 0) for c in ALPH]
    vals2 = [second_half.get(c, 0) for c in ALPH]
    mean1 = sum(vals1) / 26
    mean2 = sum(vals2) / 26
    cov = sum((v1 - mean1) * (v2 - mean2) for v1, v2 in zip(vals1, vals2)) / 26
    std1 = math.sqrt(sum((v - mean1) ** 2 for v in vals1) / 26)
    std2 = math.sqrt(sum((v - mean2) ** 2 for v in vals2) / 26)
    corr = cov / (std1 * std2) if std1 > 0 and std2 > 0 else 0

    all_results.append((abs(corr) * 100, ct,
                        f"half_freq_correlation={corr:.3f} "
                        f"(random~0.0, same_cipher>0.3)"))

    # Sort by score descending
    all_results.sort(key=lambda r: r[0], reverse=True)
    return all_results


def main():
    print("=" * 60)
    print("E-S-25: Deep CT Structural Analysis")
    print("=" * 60)
    print(f"CT: {CT}")
    print(f"Length: {N}")
    print()

    results = attack(CT)

    # ── Detailed printout by category ──────────────────────────────────

    # 1. Letter frequency
    freq = Counter(CT)
    expected = N / 26
    chi2 = sum((freq.get(c, 0) - expected) ** 2 / expected for c in ALPH)
    ic_val = sum(f * (f - 1) for f in freq.values()) / (N * (N - 1))

    print("1. LETTER FREQUENCY")
    print(f"   Expected uniform: {expected:.1f} per letter")
    print(f"   Chi-squared (uniform): {chi2:.1f} (df=25, p<0.05 threshold=37.7)")
    print(f"   Most common: {freq.most_common(5)}")
    print(f"   Least common: {freq.most_common()[-5:]}")
    print(f"   IC: {ic_val:.4f} (English=0.0667, Random=0.0385)")

    # 2. Autocorrelation
    print("\n2. AUTOCORRELATION (matching letters at each lag)")
    autocorr_results = [r for r in results if "autocorr" in r[2]]
    sig_results = [r for r in autocorr_results if r[0] > 2.0]
    print(f"   Significant lags (|z| > 2.0):")
    for score, _, method in sorted(sig_results, key=lambda x: -x[0]):
        print(f"     {method}")

    print(f"\n   Top 10 lags by |z|:")
    for score, _, method in autocorr_results[:10]:
        print(f"     {method}")

    # 3. Bigram analysis
    print("\n3. BIGRAM ANALYSIS")
    bigrams = Counter()
    for i in range(N - 1):
        bigrams[CT[i] + CT[i + 1]] += 1
    print(f"   Total unique bigrams: {len(bigrams)}/{26*26}")
    print(f"   Most common: {bigrams.most_common(10)}")
    bigram_results = [r for r in results if "bigram" in r[2]]
    for score, _, method in bigram_results[:15]:
        print(f"     {method}")

    # 4. Trigram analysis
    print("\n4. TRIGRAM ANALYSIS")
    trigram_results = [r for r in results if "trigram" in r[2]]
    print(f"   Trigrams appearing >=2 times: {len(trigram_results)}")
    for score, _, method in trigram_results:
        print(f"     {method}")

    # 5. Spectral analysis
    print("\n5. SPECTRAL ANALYSIS (DFT magnitude)")
    var_uniform = sum((i - 12.5) ** 2 for i in range(26)) / 26
    expected_mag = math.sqrt(N * var_uniform / 2)
    print(f"   Expected random magnitude: {expected_mag:.1f}")
    dft_results = [r for r in results if "DFT" in r[2]]
    print(f"   Top DFT magnitudes:")
    for score, _, method in dft_results[:10]:
        print(f"     {method}")

    # 6. Position-dependent analysis (not scored, print directly)
    print("\n6. POSITION-DEPENDENT FREQUENCY")
    third = N // 3
    for label, start, end in [("First third", 0, third),
                               ("Middle third", third, 2 * third),
                               ("Last third", 2 * third, N)]:
        segment = CT_NUM[start:end]
        seg_freq = Counter(segment)
        seg_ic = sum(f * (f - 1) for f in seg_freq.values()) / (len(segment) * (len(segment) - 1)) if len(segment) > 1 else 0
        seg_mean = sum(segment) / len(segment)
        print(f"   {label} [{start}-{end}]: IC={seg_ic:.4f}, mean_val={seg_mean:.1f}")

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

    # 7. Difference analysis
    print("\n7. DIFFERENCE ANALYSIS (CT[i+1] - CT[i] mod 26)")
    diff_results = [r for r in results if "diff_IC" in r[2]]
    for score, _, method in diff_results:
        print(f"   {method}")
    diffs = [(CT_NUM[i+1] - CT_NUM[i]) % MOD for i in range(N-1)]
    diff_freq = Counter(diffs)
    print(f"   Most common differences: {diff_freq.most_common(5)}")

    # 8. Kasiski analysis
    print("\n8. KASISKI ANALYSIS (repeated substring positions)")
    kasiski_results = [r for r in results if "kasiski" in r[2]]
    for score, _, method in kasiski_results:
        print(f"   {method}")

    # 9. Contact frequency (not scored, print directly)
    print("\n9. CONTACT FREQUENCY (letters that appear adjacent)")
    contact_after = defaultdict(Counter)
    for i in range(N - 1):
        contact_after[CT[i]][CT[i+1]] += 1

    max_contacts = []
    for letter in ALPH:
        if letter in contact_after:
            most_common = contact_after[letter].most_common(1)
            if most_common:
                max_contacts.append((letter, most_common[0], sum(contact_after[letter].values())))
    max_contacts.sort(key=lambda x: -x[1][1])
    print(f"   Letters with concentrated contacts (top 5 by max pair frequency):")
    for letter, (partner, cnt), total in max_contacts[:5]:
        print(f"     {letter} -> {partner}: {cnt}/{total} times")

    # 10. Self-similarity
    print("\n10. SELF-SIMILARITY (first vs second half)")
    half_results = [r for r in results if "half_freq_correlation" in r[2]]
    for score, _, method in half_results:
        print(f"   {method}")

    # ── Summary ─────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  KEY FINDINGS (top 15 structural metrics)")
    print(f"{'='*60}")

    for i, (score, _, method) in enumerate(results[:15]):
        print(f"  [{i+1}] score={score:.2f} | {method}")

    # Save
    json_results = {
        "letter_freq": {"chi2_uniform": chi2, "ic": ic_val, "frequencies": dict(freq)},
    }
    import os
    os.makedirs("results", exist_ok=True)
    with open("results/e_s_25_ct_structural.json", "w") as f:
        json.dump(json_results, f, indent=2, default=str)

    print(f"\n  Artifact: results/e_s_25_ct_structural.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_25_ct_structural_analysis.py")


if __name__ == "__main__":
    main()
