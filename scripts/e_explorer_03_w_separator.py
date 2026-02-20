#!/usr/bin/env python3
"""E-EXPLORER-03: W-Separator Dual-Group Hypothesis (Monte Carlo Validation).

The K4nundrum project claimed that splitting K4 ciphertext at W positions
creates two alternating groups with matching frequency distributions (p=0.04%).
This connects to Sanborn's "two separate systems" statement.

This script rigorously tests whether the W-separator pattern is a genuine
statistical signal or an artifact by:
1. Splitting K4 CT at W positions into alternating groups
2. Computing frequency distribution similarity (chi-squared, KL divergence)
3. Running Monte Carlo simulation (100K random texts) for the true p-value
4. Testing multiple split strategies (W-separator, other letters, random splits)
5. Checking against Bonferroni correction for 26-letter multiple testing

Usage: PYTHONPATH=src python3 -u scripts/e_explorer_03_w_separator.py
"""
import json
import os
import random
import time
from collections import Counter
from math import log2

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS,
)

random.seed(42)
t0 = time.time()

print("=" * 70)
print("E-EXPLORER-03: W-Separator Dual-Group Hypothesis")
print("=" * 70)


# ── Helper functions ──────────────────────────────────────────────

def split_at_letter(text, sep_letter):
    """Split text at positions of sep_letter, return alternating groups."""
    positions = [i for i, c in enumerate(text) if c == sep_letter]
    if not positions:
        return text, "", 0

    segments = []
    prev = 0
    for wp in positions:
        if wp > prev:
            segments.append(text[prev:wp])
        prev = wp + 1
    if prev < len(text):
        segments.append(text[prev:])

    group_a = ''.join(segments[i] for i in range(0, len(segments), 2))
    group_b = ''.join(segments[i] for i in range(1, len(segments), 2))
    return group_a, group_b, len(positions)


def freq_vector(text, alphabet=ALPH):
    """Return frequency vector (counts) for each letter."""
    counts = Counter(text)
    return [counts.get(c, 0) for c in alphabet]


def chi_squared_similarity(freq1, freq2):
    """Chi-squared statistic for similarity between two frequency distributions.
    Lower = more similar. Uses pooled frequencies as expected.
    """
    n1 = sum(freq1)
    n2 = sum(freq2)
    if n1 == 0 or n2 == 0:
        return float('inf')

    chi2 = 0.0
    for f1, f2 in zip(freq1, freq2):
        expected = (f1 + f2) / 2.0
        if expected > 0:
            chi2 += (f1 - expected) ** 2 / expected
            chi2 += (f2 - expected) ** 2 / expected
    return chi2


def total_variation_distance(freq1, freq2):
    """Total variation distance between two normalized distributions."""
    n1 = sum(freq1)
    n2 = sum(freq2)
    if n1 == 0 or n2 == 0:
        return 1.0
    p1 = [f / n1 for f in freq1]
    p2 = [f / n2 for f in freq2]
    return 0.5 * sum(abs(a - b) for a, b in zip(p1, p2))


def generate_random_text(length, letter_freq=None):
    """Generate random text with given letter frequencies (or uniform)."""
    if letter_freq is None:
        return ''.join(random.choice(ALPH) for _ in range(length))
    else:
        letters = []
        weights = []
        for c, f in letter_freq.items():
            letters.append(c)
            weights.append(f)
        return ''.join(random.choices(letters, weights=weights, k=length))


# ── Step 1: Analyze K4 W-separator split ──────────────────────────

print("\n--- Step 1: K4 W-Separator Split ---")
group_a, group_b, n_w = split_at_letter(CT, 'W')
print(f"W positions in K4: {[i for i, c in enumerate(CT) if c == 'W']}")
print(f"Number of Ws: {n_w}")
print(f"Group A (even segments): {len(group_a)} chars")
print(f"Group B (odd segments):  {len(group_b)} chars")
print(f"Letters not in groups (Ws): {CT_LEN - len(group_a) - len(group_b)}")

freq_a = freq_vector(group_a)
freq_b = freq_vector(group_b)

chi2_k4 = chi_squared_similarity(freq_a, freq_b)
tvd_k4 = total_variation_distance(freq_a, freq_b)
print(f"\nChi-squared similarity: {chi2_k4:.4f}")
print(f"Total variation distance: {tvd_k4:.4f}")


# ── Step 2: Monte Carlo — random texts split at W ────────────────

print("\n--- Step 2: Monte Carlo (100K random texts, split at W) ---")

N_MC = 100_000

# Use K4's letter frequencies for generation (more conservative test)
k4_freq = Counter(CT)

chi2_null = []
tvd_null = []

for trial in range(N_MC):
    # Generate random text with K4 letter frequencies
    rand_text = generate_random_text(CT_LEN, k4_freq)
    ga, gb, nw = split_at_letter(rand_text, 'W')

    if len(ga) == 0 or len(gb) == 0:
        continue

    fa = freq_vector(ga)
    fb = freq_vector(gb)
    chi2_null.append(chi_squared_similarity(fa, fb))
    tvd_null.append(total_variation_distance(fa, fb))

# Compute p-values
chi2_pval = sum(1 for x in chi2_null if x <= chi2_k4) / len(chi2_null)
tvd_pval = sum(1 for x in tvd_null if x <= tvd_k4) / len(tvd_null)

chi2_null_sorted = sorted(chi2_null)
tvd_null_sorted = sorted(tvd_null)

chi2_5th = chi2_null_sorted[int(0.05 * len(chi2_null_sorted))]
chi2_50th = chi2_null_sorted[int(0.50 * len(chi2_null_sorted))]
chi2_95th = chi2_null_sorted[int(0.95 * len(chi2_null_sorted))]

print(f"Monte Carlo trials: {len(chi2_null)}")
print(f"\nChi-squared (lower = more similar):")
print(f"  K4 observed: {chi2_k4:.4f}")
print(f"  Null 5th pctile: {chi2_5th:.4f}")
print(f"  Null 50th pctile (median): {chi2_50th:.4f}")
print(f"  Null 95th pctile: {chi2_95th:.4f}")
print(f"  p-value (P(random <= K4)): {chi2_pval:.6f}")

print(f"\nTotal variation distance (lower = more similar):")
print(f"  K4 observed: {tvd_k4:.4f}")
print(f"  Null median: {tvd_null_sorted[len(tvd_null_sorted)//2]:.4f}")
print(f"  p-value (P(random <= K4)): {tvd_pval:.6f}")


# ── Step 3: All-letters comparison (Bonferroni) ──────────────────

print("\n--- Step 3: All 26 Letters as Separators (Bonferroni) ---")

letter_results = {}
for sep_letter in ALPH:
    ga, gb, nw = split_at_letter(CT, sep_letter)
    if len(ga) < 5 or len(gb) < 5 or nw == 0:
        letter_results[sep_letter] = {'n_sep': nw, 'chi2': None, 'tvd': None, 'note': 'too few'}
        continue

    fa = freq_vector(ga)
    fb = freq_vector(gb)
    chi2_val = chi_squared_similarity(fa, fb)
    tvd_val = total_variation_distance(fa, fb)

    # Quick MC for this letter (10K trials)
    mc_chi2 = []
    for _ in range(10_000):
        rand_text = generate_random_text(CT_LEN, k4_freq)
        ra, rb, rnw = split_at_letter(rand_text, sep_letter)
        if len(ra) < 5 or len(rb) < 5:
            continue
        mc_chi2.append(chi_squared_similarity(freq_vector(ra), freq_vector(rb)))

    if mc_chi2:
        pval = sum(1 for x in mc_chi2 if x <= chi2_val) / len(mc_chi2)
    else:
        pval = 1.0

    letter_results[sep_letter] = {
        'n_sep': nw,
        'len_a': len(ga),
        'len_b': len(gb),
        'chi2': round(chi2_val, 4),
        'tvd': round(tvd_val, 4),
        'raw_pval': round(pval, 6),
    }

# Sort by raw p-value
sorted_letters = sorted(
    [(k, v) for k, v in letter_results.items() if v.get('chi2') is not None],
    key=lambda x: x[1]['raw_pval']
)

print(f"\n{'Letter':>6} | {'N_sep':>5} | {'LenA':>4} | {'LenB':>4} | {'Chi2':>8} | {'TVD':>6} | {'Raw p':>8} | {'Bonf p':>8}")
print("-" * 75)
for letter, r in sorted_letters[:10]:
    bonf_p = min(1.0, r['raw_pval'] * 26)
    marker = " **" if bonf_p < 0.05 else ""
    print(f"     {letter} | {r['n_sep']:>5} | {r['len_a']:>4} | {r['len_b']:>4} | "
          f"{r['chi2']:>8.4f} | {r['tvd']:>.4f} | {r['raw_pval']:>8.6f} | {bonf_p:>8.4f}{marker}")

# Bonferroni threshold
bonf_threshold = 0.05 / 26
any_significant = any(
    r.get('raw_pval', 1.0) < bonf_threshold
    for r in letter_results.values()
    if r.get('chi2') is not None
)

print(f"\nBonferroni threshold: {bonf_threshold:.6f}")
print(f"Any letter significant after Bonferroni: {any_significant}")


# ── Step 4: Group IC comparison ───────────────────────────────────

print("\n--- Step 4: Group IC Comparison ---")

def compute_ic(text):
    freq = Counter(text)
    n = len(text)
    if n < 2:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

ic_a = compute_ic(group_a)
ic_b = compute_ic(group_b)
ic_full = compute_ic(CT)

print(f"IC (full CT): {ic_full:.6f}")
print(f"IC (Group A): {ic_a:.6f}")
print(f"IC (Group B): {ic_b:.6f}")
print(f"IC (random):  {1/26:.6f}")
print(f"IC (English): 0.066700")

# MC p-values for group ICs
mc_ic_a = []
mc_ic_b = []
for _ in range(N_MC):
    rand_text = generate_random_text(CT_LEN, k4_freq)
    ga, gb, _ = split_at_letter(rand_text, 'W')
    if len(ga) > 1:
        mc_ic_a.append(compute_ic(ga))
    if len(gb) > 1:
        mc_ic_b.append(compute_ic(gb))

ic_a_pval = sum(1 for x in mc_ic_a if x >= ic_a) / len(mc_ic_a) if mc_ic_a else 1.0
ic_b_pval = sum(1 for x in mc_ic_b if x >= ic_b) / len(mc_ic_b) if mc_ic_b else 1.0

print(f"\np-value (IC_A >= observed): {ic_a_pval:.4f}")
print(f"p-value (IC_B >= observed): {ic_b_pval:.4f}")


# ── Step 5: Try separate decryption of groups ─────────────────────

print("\n--- Step 5: Separate Group Decryption (if meaningful) ---")

# Only proceed if the W-separator pattern was significant
if any_significant:
    print("  Pattern is significant — testing separate decryption...")
    # Test each group separately with Vigenere/Beaufort
    ct_num = [ALPH_IDX[c] for c in CT]
    crib_pt = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

    # Map CT positions to groups
    w_pos = [i for i, c in enumerate(CT) if c == 'W']
    pos_to_group = {}
    segment_idx = 0
    prev = 0
    non_w_positions = []
    for i in range(CT_LEN):
        if CT[i] == 'W':
            segment_idx += 1
            continue
        pos_to_group[i] = segment_idx % 2  # 0 or 1
        non_w_positions.append(i)

    # Count how many cribs fall in each group
    cribs_in_0 = sum(1 for p in CRIB_DICT if p in pos_to_group and pos_to_group[p] == 0)
    cribs_in_1 = sum(1 for p in CRIB_DICT if p in pos_to_group and pos_to_group[p] == 1)
    cribs_on_w = sum(1 for p in CRIB_DICT if CT[p] == 'W')
    print(f"  Cribs in group 0: {cribs_in_0}, group 1: {cribs_in_1}, on W: {cribs_on_w}")
else:
    print("  Pattern is NOT significant — skipping separate decryption.")
    print("  (No evidence the two groups represent different cipher systems.)")


# ── Summary ───────────────────────────────────────────────────────

elapsed = time.time() - t0

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  W-separator chi2: {chi2_k4:.4f} (p={chi2_pval:.6f})")
print(f"  W-separator TVD:  {tvd_k4:.4f} (p={tvd_pval:.6f})")
print(f"  Bonferroni-corrected (26 letters): p={min(1.0, chi2_pval * 26):.6f}")
print(f"  Any letter significant after Bonferroni: {any_significant}")
print(f"  Group A IC: {ic_a:.4f}, Group B IC: {ic_b:.4f}")
print(f"  Elapsed: {elapsed:.1f}s")

if chi2_pval < 0.05 and not any_significant:
    verdict = ("W shows nominally significant similarity (p<0.05) "
               "but FAILS Bonferroni correction for 26-letter multiple testing. "
               "ARTIFACT — not a genuine signal.")
elif any_significant:
    verdict = ("SIGNIFICANT after Bonferroni correction. "
               "Investigate further with separate group decryption.")
else:
    verdict = ("W-separator similarity is CONSISTENT WITH RANDOM. "
               "No evidence for dual-group structure. ARTIFACT.")

print(f"\n  VERDICT: {verdict}")
print(f"\n  Repro: PYTHONPATH=src python3 -u scripts/e_explorer_03_w_separator.py")

# Save results
results = {
    'experiment': 'E-EXPLORER-03',
    'description': 'W-separator dual-group hypothesis (Monte Carlo)',
    'w_positions': [i for i, c in enumerate(CT) if c == 'W'],
    'n_w': n_w,
    'group_a_len': len(group_a),
    'group_b_len': len(group_b),
    'chi2_observed': round(chi2_k4, 4),
    'chi2_pval': round(chi2_pval, 6),
    'tvd_observed': round(tvd_k4, 4),
    'tvd_pval': round(tvd_pval, 6),
    'bonferroni_significant': any_significant,
    'ic_group_a': round(ic_a, 6),
    'ic_group_b': round(ic_b, 6),
    'letter_results_top5': {k: v for k, v in sorted_letters[:5]},
    'verdict': verdict,
    'n_mc_trials': N_MC,
    'elapsed_seconds': round(elapsed, 1),
}

os.makedirs('artifacts', exist_ok=True)
with open('artifacts/e_explorer_03_results.json', 'w') as f:
    json.dump(results, f, indent=2)
print(f"  Artifact: artifacts/e_explorer_03_results.json")
