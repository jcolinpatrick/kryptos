#!/usr/bin/env python3
"""E-GRILLE-21: Empirical tests to distinguish scramble order for K4.

Model 1: PT -> Scramble -> Cipher -> carved text (carved IS real CT)
Model 2: PT -> Cipher -> Scramble -> carved text (carved IS scrambled CT)

Under Model 1, the carved text has normal cipher structure (periodic key
should be detectable via autocorrelation, Kasiski, bigram IC, etc.).
Under Model 2, scrambling after encryption destroys periodicity.

All prior tests found NO periodicity in the carved text. This script
quantifies exactly how the carved text compares to synthetic data from
each model, providing a principled statistical verdict.
"""

import random
import math
import sys
from collections import Counter
from typing import List, Tuple, Dict

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT

# ── Utility functions ──────────────────────────────────────────────────

def char_to_int(c: str) -> int:
    return ord(c) - ord('A')

def int_to_char(n: int) -> str:
    return chr((n % 26) + ord('A'))

def vig_encrypt(pt: str, key: str) -> str:
    """Vigenère encrypt: CT[i] = (PT[i] + KEY[i % len(key)]) mod 26."""
    out = []
    klen = len(key)
    for i, c in enumerate(pt):
        out.append(int_to_char((char_to_int(c) + char_to_int(key[i % klen])) % 26))
    return ''.join(out)

def vig_decrypt(ct: str, key: str) -> str:
    """Vigenère decrypt: PT[i] = (CT[i] - KEY[i % len(key)]) mod 26."""
    out = []
    klen = len(key)
    for i, c in enumerate(ct):
        out.append(int_to_char((char_to_int(c) - char_to_int(key[i % klen])) % 26))
    return ''.join(out)

def beaufort_decrypt(ct: str, key: str) -> str:
    """Beaufort decrypt: PT[i] = (KEY[i % len(key)] - CT[i]) mod 26."""
    out = []
    klen = len(key)
    for i, c in enumerate(ct):
        out.append(int_to_char((char_to_int(key[i % klen]) - char_to_int(c)) % 26))
    return ''.join(out)

def random_perm(n: int) -> List[int]:
    """Generate a random permutation of [0, n)."""
    p = list(range(n))
    random.shuffle(p)
    return p

def apply_perm(text: str, perm: List[int]) -> str:
    """output[i] = text[perm[i]]."""
    return ''.join(text[perm[i]] for i in range(len(perm)))

def random_english_like(n: int) -> str:
    """Generate random text with English-like letter frequencies."""
    freqs = [
        0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, 0.070, 0.002,
        0.008, 0.040, 0.024, 0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.091,
        0.028, 0.010, 0.023, 0.002, 0.020, 0.001
    ]
    cum = []
    s = 0.0
    for f in freqs:
        s += f
        cum.append(s)
    # Normalize
    cum = [c / cum[-1] for c in cum]
    out = []
    for _ in range(n):
        r = random.random()
        for j, c in enumerate(cum):
            if r <= c:
                out.append(chr(j + ord('A')))
                break
    return ''.join(out)


# ── Statistical measures ───────────────────────────────────────────────

def compute_ic(text: str) -> float:
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))

def bigram_ic(text: str) -> float:
    """Bigram index of coincidence (kappa-2)."""
    n = len(text) - 1
    if n < 2:
        return 0.0
    bigrams = [text[i:i+2] for i in range(n)]
    counts = Counter(bigrams)
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))

def trigram_ic(text: str) -> float:
    """Trigram index of coincidence."""
    n = len(text) - 2
    if n < 2:
        return 0.0
    trigrams = [text[i:i+3] for i in range(n)]
    counts = Counter(trigrams)
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))

def autocorrelation(text: str, lag: int) -> float:
    """Fraction of positions where text[i] == text[i+lag]."""
    matches = 0
    n = len(text) - lag
    if n <= 0:
        return 0.0
    for i in range(n):
        if text[i] == text[i + lag]:
            matches += 1
    return matches / n

def kasiski_repeats(text: str, ngram_len: int = 3) -> List[int]:
    """Find spacings between repeated n-grams."""
    positions: Dict[str, List[int]] = {}
    for i in range(len(text) - ngram_len + 1):
        ng = text[i:i + ngram_len]
        positions.setdefault(ng, []).append(i)
    spacings = []
    for ng, pos_list in positions.items():
        if len(pos_list) >= 2:
            for i in range(len(pos_list)):
                for j in range(i + 1, len(pos_list)):
                    spacings.append(pos_list[j] - pos_list[i])
    return spacings

def contact_frequency_chi2(text: str) -> float:
    """Chi-squared test of bigram distribution vs independence assumption.

    Under independence, P(AB) = P(A)*P(B). Compute chi-squared statistic
    comparing observed bigram counts to expected under independence.
    """
    n = len(text) - 1
    if n < 1:
        return 0.0

    # Unigram frequencies (use actual counts)
    uni_counts = Counter(text)
    total_chars = len(text)

    # Bigram counts
    bi_counts = Counter(text[i:i+2] for i in range(n))

    chi2 = 0.0
    for a in ALPH:
        for b in ALPH:
            bg = a + b
            observed = bi_counts.get(bg, 0)
            # Expected under independence
            # P(a at pos i) * P(b at pos i+1) * n
            expected = (uni_counts.get(a, 0) / total_chars) * (uni_counts.get(b, 0) / total_chars) * n
            if expected > 0:
                chi2 += (observed - expected) ** 2 / expected

    return chi2

def period_mutual_info(text: str, period: int) -> float:
    """Mutual information between residue classes at a given period.

    Under periodic substitution, chars at positions with same residue
    mod period are encrypted with same key -> their distribution should
    differ from other residue classes.
    """
    n = len(text)
    residues: Dict[int, List[str]] = {}
    for i, c in enumerate(text):
        r = i % period
        residues.setdefault(r, []).append(c)

    # Compute per-residue frequency distributions
    overall = Counter(text)

    # Compute chi-squared for each residue class vs overall distribution
    total_chi2 = 0.0
    for r in range(period):
        chars = residues.get(r, [])
        if len(chars) < 3:
            continue
        local_counts = Counter(chars)
        local_n = len(chars)
        for letter in ALPH:
            observed = local_counts.get(letter, 0)
            expected = (overall.get(letter, 0) / n) * local_n
            if expected > 0:
                total_chi2 += (observed - expected) ** 2 / expected

    return total_chi2

def max_autocorrelation(text: str, max_lag: int = 48) -> Tuple[int, float]:
    """Find the lag with maximum autocorrelation."""
    best_lag = 1
    best_val = 0.0
    for lag in range(1, min(max_lag + 1, len(text))):
        ac = autocorrelation(text, lag)
        if ac > best_val:
            best_val = ac
            best_lag = lag
    return best_lag, best_val

def count_repeated_bigrams(text: str) -> int:
    """Count number of distinct bigrams that appear more than once."""
    bigrams = [text[i:i+2] for i in range(len(text) - 1)]
    counts = Counter(bigrams)
    return sum(1 for c in counts.values() if c >= 2)

def count_repeated_trigrams(text: str) -> int:
    """Count number of distinct trigrams that appear more than once."""
    trigrams = [text[i:i+3] for i in range(len(text) - 2)]
    counts = Counter(trigrams)
    return sum(1 for c in counts.values() if c >= 2)


# ── Test implementations ───────────────────────────────────────────────

def test_1_bigram_trigram_analysis():
    """Test 1: Bigram/trigram IC analysis."""
    print("=" * 72)
    print("TEST 1: Bigram & Trigram IC Analysis")
    print("=" * 72)

    k4_bigram_ic = bigram_ic(CT)
    k4_trigram_ic = trigram_ic(CT)
    k4_repeated_bi = count_repeated_bigrams(CT)
    k4_repeated_tri = count_repeated_trigrams(CT)

    print(f"K4 carved text:")
    print(f"  Bigram IC:          {k4_bigram_ic:.6f}")
    print(f"  Trigram IC:         {k4_trigram_ic:.6f}")
    print(f"  Repeated bigrams:   {k4_repeated_bi}")
    print(f"  Repeated trigrams:  {k4_repeated_tri}")

    # Expected for random 26-letter text
    random_bigram_ic = 1.0 / (26 * 26)
    print(f"\n  Expected bigram IC (random):  {random_bigram_ic:.6f}")

    # Monte Carlo: compare to Vig-encrypted text (Model 1) and scrambled Vig text (Model 2)
    keys_to_test = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
    n_sim = 5000

    for key in keys_to_test:
        m1_bigram_ics = []
        m2_bigram_ics = []
        m1_repeated_bi = []
        m2_repeated_bi = []

        for _ in range(n_sim):
            pt = random_english_like(97)

            # Model 1: scramble PT then encrypt
            perm = random_perm(97)
            scrambled_pt = apply_perm(pt, perm)
            m1_ct = vig_encrypt(scrambled_pt, key)

            # Model 2: encrypt then scramble
            real_ct = vig_encrypt(pt, key)
            m2_ct = apply_perm(real_ct, perm)

            m1_bigram_ics.append(bigram_ic(m1_ct))
            m2_bigram_ics.append(bigram_ic(m2_ct))
            m1_repeated_bi.append(count_repeated_bigrams(m1_ct))
            m2_repeated_bi.append(count_repeated_bigrams(m2_ct))

        m1_mean_bi = sum(m1_bigram_ics) / len(m1_bigram_ics)
        m2_mean_bi = sum(m2_bigram_ics) / len(m2_bigram_ics)
        m1_mean_rep = sum(m1_repeated_bi) / len(m1_repeated_bi)
        m2_mean_rep = sum(m2_repeated_bi) / len(m2_repeated_bi)

        print(f"\n  Key={key}, {n_sim} sims:")
        print(f"    Model 1 mean bigram IC: {m1_mean_bi:.6f}")
        print(f"    Model 2 mean bigram IC: {m2_mean_bi:.6f}")
        print(f"    Model 1 mean repeated bigrams: {m1_mean_rep:.1f}")
        print(f"    Model 2 mean repeated bigrams: {m2_mean_rep:.1f}")

    return k4_bigram_ic, k4_trigram_ic


def test_2_kasiski():
    """Test 2: Kasiski examination."""
    print("\n" + "=" * 72)
    print("TEST 2: Kasiski Examination")
    print("=" * 72)

    for ng_len in [2, 3, 4]:
        k4_spacings = kasiski_repeats(CT, ng_len)
        print(f"\n  {ng_len}-gram repeats in K4: {len(k4_spacings)} spacings")
        if k4_spacings:
            # Check for GCD patterns (would indicate period)
            from math import gcd
            from functools import reduce
            if len(k4_spacings) >= 2:
                g = reduce(gcd, k4_spacings)
                print(f"  GCD of all spacings: {g}")
            # Factor analysis
            factor_counts = Counter()
            for s in k4_spacings:
                for f in range(2, min(s + 1, 30)):
                    if s % f == 0:
                        factor_counts[f] += 1
            if factor_counts:
                top_factors = factor_counts.most_common(5)
                print(f"  Top factors: {top_factors}")

    # Monte Carlo comparison
    n_sim = 5000
    key = "KRYPTOS"
    m1_counts_3 = []
    m2_counts_3 = []

    for _ in range(n_sim):
        pt = random_english_like(97)
        perm = random_perm(97)

        # Model 1
        m1_ct = vig_encrypt(apply_perm(pt, perm), key)
        m1_spacings = kasiski_repeats(m1_ct, 3)
        m1_counts_3.append(len(m1_spacings))

        # Model 2
        m2_ct = apply_perm(vig_encrypt(pt, key), perm)
        m2_spacings = kasiski_repeats(m2_ct, 3)
        m2_counts_3.append(len(m2_spacings))

    k4_3gram_spacings = len(kasiski_repeats(CT, 3))
    print(f"\n  K4 trigram spacing count: {k4_3gram_spacings}")
    print(f"  Model 1 (KRYPTOS) mean: {sum(m1_counts_3)/len(m1_counts_3):.1f}")
    print(f"  Model 2 (KRYPTOS) mean: {sum(m2_counts_3)/len(m2_counts_3):.1f}")
    m1_below = sum(1 for x in m1_counts_3 if x <= k4_3gram_spacings) / n_sim
    m2_below = sum(1 for x in m2_counts_3 if x <= k4_3gram_spacings) / n_sim
    print(f"  P(count <= K4 | Model 1): {m1_below:.4f}")
    print(f"  P(count <= K4 | Model 2): {m2_below:.4f}")


def test_3_autocorrelation():
    """Test 3: Autocorrelation at all lags."""
    print("\n" + "=" * 72)
    print("TEST 3: Autocorrelation at All Lags 1-48")
    print("=" * 72)

    print("\n  K4 autocorrelation:")
    k4_acs = []
    for lag in range(1, 49):
        ac = autocorrelation(CT, lag)
        k4_acs.append(ac)
        marker = " ***" if ac > 0.06 else ""
        if lag <= 30 or ac > 0.06:
            print(f"    lag {lag:2d}: {ac:.4f}{marker}")

    best_lag, best_ac = max_autocorrelation(CT, 48)
    print(f"\n  Best lag: {best_lag} with AC={best_ac:.4f}")

    # Expected AC for random text
    expected_random = 1.0 / 26
    print(f"  Expected random AC: {expected_random:.4f}")

    # Monte Carlo: compare peak AC
    n_sim = 5000
    key = "KRYPTOS"
    m1_peaks = []
    m2_peaks = []
    m1_at_period = []
    m2_at_period = []
    period = len(key)  # 7

    for _ in range(n_sim):
        pt = random_english_like(97)
        perm = random_perm(97)

        m1_ct = vig_encrypt(apply_perm(pt, perm), key)
        m2_ct = apply_perm(vig_encrypt(pt, key), perm)

        _, m1_peak = max_autocorrelation(m1_ct, 48)
        _, m2_peak = max_autocorrelation(m2_ct, 48)
        m1_peaks.append(m1_peak)
        m2_peaks.append(m2_peak)

        m1_at_period.append(autocorrelation(m1_ct, period))
        m2_at_period.append(autocorrelation(m2_ct, period))

    print(f"\n  Monte Carlo ({n_sim} sims, key={key}):")
    print(f"    Model 1 mean peak AC:       {sum(m1_peaks)/len(m1_peaks):.4f}")
    print(f"    Model 2 mean peak AC:       {sum(m2_peaks)/len(m2_peaks):.4f}")
    print(f"    Model 1 mean AC at period {period}: {sum(m1_at_period)/len(m1_at_period):.4f}")
    print(f"    Model 2 mean AC at period {period}: {sum(m2_at_period)/len(m2_at_period):.4f}")

    return k4_acs


def test_4_period_log_likelihood():
    """Test 4: Log-likelihood ratio for each period."""
    print("\n" + "=" * 72)
    print("TEST 4: Period-wise Chi-squared (Residue Class Homogeneity)")
    print("=" * 72)

    print("\n  K4 chi-squared by period:")
    k4_chi2s = {}
    for p in range(2, 27):
        chi2 = period_mutual_info(CT, p)
        k4_chi2s[p] = chi2
        df = (p - 1) * 25  # degrees of freedom approx
        normalized = chi2 / df if df > 0 else 0
        marker = " ***" if normalized > 1.5 else ""
        print(f"    period {p:2d}: chi2={chi2:7.1f}  (df={df:3d}, chi2/df={normalized:.3f}){marker}")

    # Monte Carlo comparison for specific periods
    n_sim = 3000
    for key_name, key in [("KRYPTOS", "KRYPTOS"), ("PALIMPSEST", "PALIMPSEST"), ("ABSCISSA", "ABSCISSA")]:
        period = len(key)
        print(f"\n  Monte Carlo for period {period} (key={key_name}, {n_sim} sims):")

        m1_chi2s = []
        m2_chi2s = []

        for _ in range(n_sim):
            pt = random_english_like(97)
            perm = random_perm(97)

            m1_ct = vig_encrypt(apply_perm(pt, perm), key)
            m2_ct = apply_perm(vig_encrypt(pt, key), perm)

            m1_chi2s.append(period_mutual_info(m1_ct, period))
            m2_chi2s.append(period_mutual_info(m2_ct, period))

        k4_val = k4_chi2s[period]
        m1_mean = sum(m1_chi2s) / len(m1_chi2s)
        m2_mean = sum(m2_chi2s) / len(m2_chi2s)

        print(f"    K4 chi2 at period {period}: {k4_val:.1f}")
        print(f"    Model 1 mean chi2:       {m1_mean:.1f}")
        print(f"    Model 2 mean chi2:       {m2_mean:.1f}")

        m1_below = sum(1 for x in m1_chi2s if x <= k4_val) / n_sim
        m2_below = sum(1 for x in m2_chi2s if x <= k4_val) / n_sim
        print(f"    P(chi2 <= K4 | Model 1): {m1_below:.4f}")
        print(f"    P(chi2 <= K4 | Model 2): {m2_below:.4f}")


def test_5_contact_frequency():
    """Test 5: Contact frequency / bigram chi-squared."""
    print("\n" + "=" * 72)
    print("TEST 5: Contact Frequency (Bigram Chi-squared vs Independence)")
    print("=" * 72)

    k4_chi2 = contact_frequency_chi2(CT)
    print(f"\n  K4 bigram chi2: {k4_chi2:.1f}")

    # Monte Carlo
    n_sim = 5000
    keys = [("KRYPTOS", "KRYPTOS"), ("PALIMPSEST", "PALIMPSEST")]

    for key_name, key in keys:
        m1_chi2s = []
        m2_chi2s = []

        for _ in range(n_sim):
            pt = random_english_like(97)
            perm = random_perm(97)

            m1_ct = vig_encrypt(apply_perm(pt, perm), key)
            m2_ct = apply_perm(vig_encrypt(pt, key), perm)

            m1_chi2s.append(contact_frequency_chi2(m1_ct))
            m2_chi2s.append(contact_frequency_chi2(m2_ct))

        m1_mean = sum(m1_chi2s) / len(m1_chi2s)
        m2_mean = sum(m2_chi2s) / len(m2_chi2s)

        print(f"\n  Key={key_name}, {n_sim} sims:")
        print(f"    Model 1 mean bigram chi2: {m1_mean:.1f}")
        print(f"    Model 2 mean bigram chi2: {m2_mean:.1f}")
        print(f"    K4 bigram chi2:           {k4_chi2:.1f}")

        m1_below = sum(1 for x in m1_chi2s if x <= k4_chi2) / n_sim
        m2_below = sum(1 for x in m2_chi2s if x <= k4_chi2) / n_sim
        print(f"    P(chi2 <= K4 | Model 1): {m1_below:.4f}")
        print(f"    P(chi2 <= K4 | Model 2): {m2_below:.4f}")


def test_6_reverse_decryption():
    """Test 6: Direct decryption of carved text with known keys."""
    print("\n" + "=" * 72)
    print("TEST 6: Direct Decryption IC Test")
    print("=" * 72)
    print("  If Model 1: decrypting with correct key -> scrambled PT (IC ~0.065)")
    print("  If Model 2: decrypting with correct key -> garbage (IC ~0.038)")

    k4_ic = compute_ic(CT)
    print(f"\n  K4 carved text IC: {k4_ic:.4f}")

    keys_to_test = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "K", "KR", "KRY", "KRYP", "KRYPT", "KRYPTO"]

    print("\n  Vigenère decryption:")
    for key in keys_to_test:
        pt_vig = vig_decrypt(CT, key)
        ic_vig = compute_ic(pt_vig)
        marker = " *** ELEVATED" if ic_vig > 0.050 else ""
        print(f"    Key={key:12s}  IC={ic_vig:.4f}{marker}")

    print("\n  Beaufort decryption:")
    for key in keys_to_test:
        pt_beau = beaufort_decrypt(CT, key)
        ic_beau = compute_ic(pt_beau)
        marker = " *** ELEVATED" if ic_beau > 0.050 else ""
        print(f"    Key={key:12s}  IC={ic_beau:.4f}{marker}")

    # What WOULD we expect under Model 1 with correct key?
    print("\n  Expected IC under Model 1 (correct key -> scrambled English PT):")
    print("    Scrambling preserves IC -> should see IC ~0.065 (English)")
    print("  Expected IC under Model 2 (wrong approach, decrypting scrambled CT):")
    print("    IC should stay near ciphertext level ~0.038")


def test_7_letter_frequency_ic():
    """Test 7: IC analysis — what does below-random IC tell us?"""
    print("\n" + "=" * 72)
    print("TEST 7: Letter Frequency & IC Analysis")
    print("=" * 72)

    k4_ic = compute_ic(CT)
    k4_counts = Counter(CT)

    print(f"\n  K4 IC: {k4_ic:.4f}")
    print(f"  Random expected IC: {1/26:.4f}")
    print(f"  English IC: ~0.0667")
    print(f"  Vig-encrypted English IC (period ~7): ~0.045")

    # Under Model 1: IC of CT = IC of vig-encrypted scrambled-PT
    #   Scrambling doesn't change letter frequencies, so scrambled PT has
    #   English-like IC. Vig encryption with period p reduces IC.
    # Under Model 2: IC of carved text = IC of real CT (preserved by permutation)
    #   Real CT has same IC as Vig-encrypted PT.
    # => BOTH MODELS predict the same IC for the carved text! (IC is perm-invariant)

    print("\n  CRITICAL INSIGHT: IC is invariant under permutation!")
    print("  Both models predict the same IC for the carved text.")
    print("  IC = 0.0361 tells us about the substitution cipher regardless of model.")

    # Monte Carlo: verify IC invariance
    n_sim = 5000
    key = "KRYPTOS"
    m1_ics = []
    m2_ics = []

    for _ in range(n_sim):
        pt = random_english_like(97)
        perm = random_perm(97)

        m1_ct = vig_encrypt(apply_perm(pt, perm), key)
        m2_ct = apply_perm(vig_encrypt(pt, key), perm)

        m1_ics.append(compute_ic(m1_ct))
        m2_ics.append(compute_ic(m2_ct))

    m1_mean = sum(m1_ics) / len(m1_ics)
    m2_mean = sum(m2_ics) / len(m2_ics)

    print(f"\n  Monte Carlo verification ({n_sim} sims, key={key}):")
    print(f"    Model 1 mean IC: {m1_mean:.4f}")
    print(f"    Model 2 mean IC: {m2_mean:.4f}")
    print(f"    (Should be identical — IC is permutation-invariant)")

    # What PERIODS are consistent with IC=0.0361?
    print("\n  IC vs period (Friedman's formula for Vigenère):")
    print("    IC ≈ (1/p)*IC_english + (1 - 1/p)*IC_random")
    ic_eng = 0.0667
    ic_rand = 1.0 / 26
    for p in [2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 16, 20, 26]:
        expected_ic = (1.0 / p) * ic_eng + (1.0 - 1.0 / p) * ic_rand
        marker = " <-- close to K4" if abs(expected_ic - k4_ic) < 0.003 else ""
        print(f"    period {p:2d}: expected IC={expected_ic:.4f}{marker}")

    # Sorted letter frequencies
    print("\n  K4 letter frequencies (sorted):")
    for ch, cnt in k4_counts.most_common():
        bar = "#" * cnt
        print(f"    {ch}: {cnt:2d} {bar}")


def test_8_monte_carlo_comprehensive():
    """Test 8: Comprehensive Monte Carlo — multi-statistic comparison."""
    print("\n" + "=" * 72)
    print("TEST 8: Comprehensive Monte Carlo Simulation")
    print("=" * 72)

    n_sim = 5000

    # Compute K4 statistics
    k4_stats = {
        'ic': compute_ic(CT),
        'bigram_ic': bigram_ic(CT),
        'peak_ac': max_autocorrelation(CT, 48)[1],
        'contact_chi2': contact_frequency_chi2(CT),
        'repeated_bi': count_repeated_bigrams(CT),
        'repeated_tri': count_repeated_trigrams(CT),
    }

    print(f"\n  K4 statistics:")
    for stat, val in k4_stats.items():
        print(f"    {stat:20s}: {val:.6f}" if isinstance(val, float) else f"    {stat:20s}: {val}")

    keys_to_test = [("KRYPTOS", "KRYPTOS"), ("PALIMPSEST", "PALIMPSEST")]

    for key_name, key in keys_to_test:
        print(f"\n  --- Key={key_name}, {n_sim} simulations ---")

        m1_stats = {k: [] for k in k4_stats}
        m2_stats = {k: [] for k in k4_stats}

        for _ in range(n_sim):
            pt = random_english_like(97)
            perm = random_perm(97)

            m1_ct = vig_encrypt(apply_perm(pt, perm), key)
            m2_ct = apply_perm(vig_encrypt(pt, key), perm)

            for text, stats in [(m1_ct, m1_stats), (m2_ct, m2_stats)]:
                stats['ic'].append(compute_ic(text))
                stats['bigram_ic'].append(bigram_ic(text))
                stats['peak_ac'].append(max_autocorrelation(text, 48)[1])
                stats['contact_chi2'].append(contact_frequency_chi2(text))
                stats['repeated_bi'].append(count_repeated_bigrams(text))
                stats['repeated_tri'].append(count_repeated_trigrams(text))

        print(f"\n  {'Statistic':20s} | {'K4':>10s} | {'M1 mean':>10s} | {'M2 mean':>10s} | {'M1 std':>10s} | {'M2 std':>10s} | {'P(<=K4|M1)':>10s} | {'P(<=K4|M2)':>10s}")
        print("  " + "-" * 108)

        for stat in k4_stats:
            k4_val = k4_stats[stat]
            m1_vals = m1_stats[stat]
            m2_vals = m2_stats[stat]

            m1_mean = sum(m1_vals) / len(m1_vals)
            m2_mean = sum(m2_vals) / len(m2_vals)
            m1_std = (sum((x - m1_mean) ** 2 for x in m1_vals) / len(m1_vals)) ** 0.5
            m2_std = (sum((x - m2_mean) ** 2 for x in m2_vals) / len(m2_vals)) ** 0.5

            m1_p = sum(1 for x in m1_vals if x <= k4_val) / n_sim
            m2_p = sum(1 for x in m2_vals if x <= k4_val) / n_sim

            if isinstance(k4_val, float):
                print(f"  {stat:20s} | {k4_val:10.6f} | {m1_mean:10.6f} | {m2_mean:10.6f} | {m1_std:10.6f} | {m2_std:10.6f} | {m1_p:10.4f} | {m2_p:10.4f}")
            else:
                print(f"  {stat:20s} | {k4_val:10d} | {m1_mean:10.2f} | {m2_mean:10.2f} | {m1_std:10.2f} | {m2_std:10.2f} | {m1_p:10.4f} | {m2_p:10.4f}")

    # Additional: Model 1 with scrambled input STILL has periodic key
    # operating on consecutive positions -> should show structure.
    # Model 2 has lost that structure. The KEY discriminator is whether
    # consecutive positions in the carved text share periodic key relationships.

    print("\n  KEY INTERPRETATION:")
    print("    Under Model 1, the Vigenère key operates on the carved text directly.")
    print("    Consecutive positions share periodic key -> serial correlation exists.")
    print("    Under Model 2, the Vigenère key operated on pre-scrambled positions.")
    print("    Consecutive carved positions are from DIFFERENT key positions -> no serial correlation.")
    print("    => Tests that detect SERIAL STRUCTURE (bigram IC, autocorrelation,")
    print("       contact chi-squared) should discriminate between models.")
    print("    => IC is invariant under permutation, so it CANNOT discriminate.")


def test_overall_verdict():
    """Synthesize results into a verdict."""
    print("\n" + "=" * 72)
    print("OVERALL VERDICT")
    print("=" * 72)

    # The key insight: Model 1 preserves Vigenère serial structure.
    # Model 2 destroys it. K4 shows NO serial structure.

    # Quick computation: does K4 show ANY periodic signal?
    best_lag, best_ac = max_autocorrelation(CT, 48)
    k4_contact = contact_frequency_chi2(CT)
    k4_bi_ic = bigram_ic(CT)

    # Compare to what Model 1 (Vig with KRYPTOS) SHOULD show
    key = "KRYPTOS"
    n_sim = 5000

    m1_contact = []
    m2_contact = []
    m1_peak_acs = []
    m2_peak_acs = []

    for _ in range(n_sim):
        pt = random_english_like(97)
        perm = random_perm(97)

        m1_ct = vig_encrypt(apply_perm(pt, perm), key)
        m2_ct = apply_perm(vig_encrypt(pt, key), perm)

        m1_contact.append(contact_frequency_chi2(m1_ct))
        m2_contact.append(contact_frequency_chi2(m2_ct))
        m1_peak_acs.append(max_autocorrelation(m1_ct, 48)[1])
        m2_peak_acs.append(max_autocorrelation(m2_ct, 48)[1])

    m1_c_mean = sum(m1_contact) / len(m1_contact)
    m2_c_mean = sum(m2_contact) / len(m2_contact)
    m1_ac_mean = sum(m1_peak_acs) / len(m1_peak_acs)
    m2_ac_mean = sum(m2_peak_acs) / len(m2_peak_acs)

    print(f"\n  Contact chi-squared: K4={k4_contact:.1f}, M1 mean={m1_c_mean:.1f}, M2 mean={m2_c_mean:.1f}")
    print(f"  Peak autocorrelation: K4={best_ac:.4f}, M1 mean={m1_ac_mean:.4f}, M2 mean={m2_ac_mean:.4f}")

    # Where does K4 fall?
    m1_c_above = sum(1 for x in m1_contact if x >= k4_contact) / n_sim
    m2_c_above = sum(1 for x in m2_contact if x >= k4_contact) / n_sim
    m1_ac_above = sum(1 for x in m1_peak_acs if x >= best_ac) / n_sim
    m2_ac_above = sum(1 for x in m2_peak_acs if x >= best_ac) / n_sim

    print(f"\n  P(contact_chi2 >= K4 | Model 1): {m1_c_above:.4f}")
    print(f"  P(contact_chi2 >= K4 | Model 2): {m2_c_above:.4f}")
    print(f"  P(peak_AC >= K4 | Model 1):      {m1_ac_above:.4f}")
    print(f"  P(peak_AC >= K4 | Model 2):      {m2_ac_above:.4f}")

    # Combined p-value-like measure
    # Under Model 1, we expect HIGHER contact chi2 and HIGHER peak AC
    # (because Vig serial structure is present)
    # If K4 is LOW on both, it disfavors Model 1

    m1_both_below = sum(
        1 for c, a in zip(m1_contact, m1_peak_acs)
        if c <= k4_contact and a <= best_ac
    ) / n_sim
    m2_both_below = sum(
        1 for c, a in zip(m2_contact, m2_peak_acs)
        if c <= k4_contact and a <= best_ac
    ) / n_sim

    print(f"\n  Joint P(contact<=K4 AND peak_ac<=K4 | Model 1): {m1_both_below:.4f}")
    print(f"  Joint P(contact<=K4 AND peak_ac<=K4 | Model 2): {m2_both_below:.4f}")

    if m2_both_below > m1_both_below * 2:
        print("\n  VERDICT: K4's statistical profile is MORE CONSISTENT with Model 2")
        print("  (cipher first, then scramble). The carved text lacks the serial")
        print("  structure expected from a Vigenère cipher operating directly.")
    elif m1_both_below > m2_both_below * 2:
        print("\n  VERDICT: K4's statistical profile is MORE CONSISTENT with Model 1")
        print("  (scramble first, then cipher). The carved text shows serial structure.")
    else:
        print("\n  VERDICT: INCONCLUSIVE — K4 statistics do not clearly favor either model.")
        print("  This may indicate:")
        print("  - The key period is very long (weakening serial correlation)")
        print("  - The cipher is not standard Vigenère")
        print("  - 97 characters is too short for reliable discrimination")

    # Additional check: what if the key is very long?
    print("\n  SENSITIVITY CHECK: Does key length matter?")
    for klen in [3, 5, 7, 10, 13, 20, 26, 50, 97]:
        key_test = ''.join(chr(random.randint(65, 90)) for _ in range(klen))
        m1_c_vals = []
        m2_c_vals = []
        n_check = 2000

        for _ in range(n_check):
            pt = random_english_like(97)
            perm = random_perm(97)

            m1_ct = vig_encrypt(apply_perm(pt, perm), key_test)
            m2_ct = apply_perm(vig_encrypt(pt, key_test), perm)

            m1_c_vals.append(contact_frequency_chi2(m1_ct))
            m2_c_vals.append(contact_frequency_chi2(m2_ct))

        m1_m = sum(m1_c_vals) / len(m1_c_vals)
        m2_m = sum(m2_c_vals) / len(m2_c_vals)
        diff = m1_m - m2_m
        ratio = m1_m / m2_m if m2_m > 0 else float('inf')
        print(f"    Key length {klen:2d}: M1 mean contact={m1_m:.1f}, M2 mean={m2_m:.1f}, "
              f"diff={diff:.1f}, ratio={ratio:.3f}")


# ── Main ───────────────────────────────────────────────────────────────

def main():
    print("E-GRILLE-21: Empirical Scramble Order Tests for K4")
    print("=" * 72)
    print(f"K4 carved text ({CT_LEN} chars): {CT}")
    print(f"\nModel 1: PT -> Scramble -> Cipher -> carved text")
    print(f"Model 2: PT -> Cipher -> Scramble -> carved text")
    print(f"\nUnder Model 1, carved text IS genuine ciphertext (periodic key detectable)")
    print(f"Under Model 2, carved text is scrambled CT (periodicity destroyed)")

    random.seed(42)  # Reproducibility

    test_1_bigram_trigram_analysis()
    test_2_kasiski()
    test_3_autocorrelation()
    test_4_period_log_likelihood()
    test_5_contact_frequency()
    test_6_reverse_decryption()
    test_7_letter_frequency_ic()
    test_8_monte_carlo_comprehensive()
    test_overall_verdict()

    print("\n" + "=" * 72)
    print("DONE")
    print("=" * 72)


if __name__ == "__main__":
    main()
