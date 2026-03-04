#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-54: Pre-ENE Segment Deep Analysis (RQ-7).

Positions 0-20 of K4 (OBKRUOXOGHULBSOLIFBBW) have IC=0.0667, which matches
English. This is notable because the full K4 IC is 0.0361 (below random).

This experiment systematically investigates:
1. Frequency analysis and comparison to English
2. Mono-alphabetic substitution attempts (best-fit mapping to English)
3. Caesar/affine shifts
4. Whether positions 0-20 could be a key indicator group
5. Whether the IC is just a statistical artifact (letter repetition pattern)
6. Bigram/trigram analysis
7. Relationship to rest of CT (positions 21-96)

Key question: Is the pre-ENE segment structurally different from the rest of K4,
or is the English-like IC just a coincidence of the small sample size?
"""

import json
import math
import time
import sys
from collections import Counter

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET,
)

# ── Constants ────────────────────────────────────────────────────────
PRE_ENE = CT[:21]   # OBKRUOXOGHULBSOLIFBBW
POST_ENE = CT[21:]  # positions 21-96 (76 chars, includes cribs)
ENE_CRIB = CT[21:34]  # positions 21-33
BC_CRIB = CT[63:74]   # positions 63-73

# English single-letter frequencies (from standard corpus)
ENG_FREQ = {
    'A': 0.0817, 'B': 0.0150, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}


def compute_ic(text):
    """Compute Index of Coincidence."""
    n = len(text)
    if n <= 1:
        return 0.0
    counts = Counter(text)
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))


def compute_chi2(text, expected_freq=None):
    """Chi-squared statistic against expected frequencies."""
    if expected_freq is None:
        expected_freq = ENG_FREQ
    n = len(text)
    counts = Counter(text)
    chi2 = 0.0
    for c in ALPH:
        obs = counts.get(c, 0)
        exp = expected_freq[c] * n
        if exp > 0:
            chi2 += (obs - exp) ** 2 / exp
    return chi2


def caesar_decrypt(text, shift):
    """Decrypt with Caesar cipher (shift each letter back by shift)."""
    return ''.join(ALPH[(ALPH_IDX[c] - shift) % MOD] for c in text)


def affine_decrypt(text, a, b):
    """Decrypt with affine cipher: PT = a_inv * (CT - b) mod 26."""
    # Find a_inv
    a_inv = None
    for x in range(MOD):
        if (a * x) % MOD == 1:
            a_inv = x
            break
    if a_inv is None:
        return None  # a not invertible
    return ''.join(ALPH[(a_inv * (ALPH_IDX[c] - b)) % MOD] for c in text)


def mono_substitution_bestfit(text):
    """Find best monoalphabetic mapping by frequency ranking."""
    counts = Counter(text)
    # Sort text letters by frequency (descending)
    text_order = sorted(ALPH, key=lambda c: -counts.get(c, 0))
    # Sort English letters by frequency (descending)
    eng_order = sorted(ALPH, key=lambda c: -ENG_FREQ[c])
    # Map: text_order[i] -> eng_order[i]
    mapping = {}
    for t, e in zip(text_order, eng_order):
        mapping[t] = e
    decrypted = ''.join(mapping[c] for c in text)
    return decrypted, mapping


def bigram_analysis(text):
    """Count bigrams and find repeated ones."""
    bigrams = Counter()
    for i in range(len(text) - 1):
        bigrams[text[i:i+2]] += 1
    repeated = {bg: cnt for bg, cnt in bigrams.items() if cnt > 1}
    return bigrams, repeated


def trigram_analysis(text):
    """Count trigrams and find repeated ones."""
    trigrams = Counter()
    for i in range(len(text) - 2):
        trigrams[text[i:i+3]] += 1
    repeated = {tg: cnt for tg, cnt in trigrams.items() if cnt > 1}
    return trigrams, repeated


def entropy(text):
    """Shannon entropy in bits."""
    n = len(text)
    counts = Counter(text)
    h = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            h -= p * math.log2(p)
    return h


def monte_carlo_ic(text_len, n_trials=100000):
    """Monte Carlo: distribution of IC for random 26-letter text of given length."""
    import random
    ics = []
    for _ in range(n_trials):
        t = ''.join(random.choice(ALPH) for _ in range(text_len))
        ics.append(compute_ic(t))
    ics.sort()
    mean_ic = sum(ics) / len(ics)
    p95 = ics[int(0.95 * len(ics))]
    p99 = ics[int(0.99 * len(ics))]
    return mean_ic, p95, p99, ics


def main():
    print("=" * 70)
    print("E-S-54: Pre-ENE Segment Deep Analysis (RQ-7)")
    print("=" * 70)
    print(f"Pre-ENE (pos 0-20): {PRE_ENE}")
    print(f"Length: {len(PRE_ENE)}")
    print()

    results = {}
    t0 = time.time()

    # ── 1. Basic frequency analysis ─────────────────────────────────
    print("=" * 50)
    print("1. FREQUENCY ANALYSIS")
    print("=" * 50)
    pre_counts = Counter(PRE_ENE)
    print(f"  Letter counts: {dict(sorted(pre_counts.items(), key=lambda x: -x[1]))}")
    print(f"  Distinct letters: {len(pre_counts)}/26")
    print(f"  Most common: {pre_counts.most_common(5)}")
    print(f"  Missing: {sorted(set(ALPH) - set(PRE_ENE))}")

    pre_ic = compute_ic(PRE_ENE)
    full_ic = compute_ic(CT)
    post_ic = compute_ic(POST_ENE)
    print(f"\n  IC (pre-ENE, 0-20):  {pre_ic:.4f}")
    print(f"  IC (full CT, 0-96):  {full_ic:.4f}")
    print(f"  IC (post, 21-96):    {post_ic:.4f}")
    print(f"  IC English:          0.0667")
    print(f"  IC random:           0.0385")

    pre_chi2 = compute_chi2(PRE_ENE)
    full_chi2 = compute_chi2(CT)
    post_chi2 = compute_chi2(POST_ENE)
    print(f"\n  Chi² vs English (pre-ENE): {pre_chi2:.1f}")
    print(f"  Chi² vs English (full):    {full_chi2:.1f}")
    print(f"  Chi² vs English (post):    {post_chi2:.1f}")
    print(f"  Chi² critical (25 df, α=0.05): 37.65")

    pre_h = entropy(PRE_ENE)
    eng_h = 4.17  # Approximate English unigram entropy
    rand_h = math.log2(26)
    print(f"\n  Entropy (pre-ENE): {pre_h:.3f} bits")
    print(f"  Entropy (English): ~{eng_h:.2f} bits")
    print(f"  Entropy (random):  {rand_h:.3f} bits")

    results["frequency"] = {
        "pre_ic": pre_ic, "full_ic": full_ic, "post_ic": post_ic,
        "pre_chi2": pre_chi2, "full_chi2": full_chi2,
        "pre_entropy": pre_h,
        "letter_counts": dict(pre_counts),
        "distinct": len(pre_counts),
    }

    # ── 2. Is IC = 0.0667 a statistical artifact? ───────────────────
    print("\n" + "=" * 50)
    print("2. IC ARTIFACT ANALYSIS (Monte Carlo)")
    print("=" * 50)
    print("  Running 100K random 21-char strings...")
    mean_ic, p95, p99, ics = monte_carlo_ic(21, 100000)
    n_above = sum(1 for x in ics if x >= pre_ic)
    pval = n_above / len(ics)
    print(f"  Random IC mean: {mean_ic:.4f}")
    print(f"  Random IC 95th: {p95:.4f}")
    print(f"  Random IC 99th: {p99:.4f}")
    print(f"  Pre-ENE IC:     {pre_ic:.4f}")
    print(f"  P(IC >= {pre_ic:.4f}): {pval:.4f} ({n_above}/{len(ics)})")

    # What drives the high IC? The repeated letters.
    print(f"\n  Repeated letters driving IC:")
    for ch, cnt in pre_counts.most_common():
        if cnt >= 2:
            contribution = cnt * (cnt - 1) / (21 * 20)
            print(f"    {ch}: {cnt} occurrences, IC contribution = {contribution:.4f}")

    results["mc_artifact"] = {
        "random_mean": mean_ic, "p95": p95, "p99": p99,
        "pvalue": pval, "n_above": n_above,
    }

    # ── 3. Caesar / Affine decryption ───────────────────────────────
    print("\n" + "=" * 50)
    print("3. CAESAR & AFFINE SHIFTS")
    print("=" * 50)
    best_caesar = None
    best_caesar_chi2 = float('inf')
    for shift in range(MOD):
        dec = caesar_decrypt(PRE_ENE, shift)
        chi2 = compute_chi2(dec)
        if chi2 < best_caesar_chi2:
            best_caesar_chi2 = chi2
            best_caesar = (shift, dec, chi2)
    print(f"  Best Caesar: shift={best_caesar[0]} chi²={best_caesar[2]:.1f}")
    print(f"    Decrypted: {best_caesar[1]}")
    print(f"    (Shift 0 = identity: {PRE_ENE})")

    # Top 5 Caesar shifts
    caesar_results = []
    for shift in range(MOD):
        dec = caesar_decrypt(PRE_ENE, shift)
        chi2 = compute_chi2(dec)
        caesar_results.append((shift, dec, chi2))
    caesar_results.sort(key=lambda x: x[2])
    print(f"\n  Top 5 Caesar shifts:")
    for shift, dec, chi2 in caesar_results[:5]:
        print(f"    shift={shift:2d} chi²={chi2:6.1f} → {dec}")

    # Affine: test all (a, b) where gcd(a, 26) = 1
    best_affine = None
    best_affine_chi2 = float('inf')
    for a in range(1, MOD):
        if math.gcd(a, MOD) != 1:
            continue
        for b in range(MOD):
            dec = affine_decrypt(PRE_ENE, a, b)
            if dec is None:
                continue
            chi2 = compute_chi2(dec)
            if chi2 < best_affine_chi2:
                best_affine_chi2 = chi2
                best_affine = (a, b, dec, chi2)
    print(f"\n  Best Affine: a={best_affine[0]} b={best_affine[1]} chi²={best_affine[3]:.1f}")
    print(f"    Decrypted: {best_affine[2]}")

    results["caesar_affine"] = {
        "best_caesar_shift": best_caesar[0],
        "best_caesar_chi2": best_caesar[2],
        "best_caesar_text": best_caesar[1],
        "best_affine_a": best_affine[0],
        "best_affine_b": best_affine[1],
        "best_affine_chi2": best_affine[3],
        "best_affine_text": best_affine[2],
    }

    # ── 4. Best-fit monoalphabetic substitution ─────────────────────
    print("\n" + "=" * 50)
    print("4. FREQUENCY-BASED MONO SUBSTITUTION")
    print("=" * 50)
    dec_mono, mapping = mono_substitution_bestfit(PRE_ENE)
    print(f"  Mapping: {mapping}")
    print(f"  Decrypted: {dec_mono}")
    chi2_mono = compute_chi2(dec_mono)
    print(f"  Chi² after mapping: {chi2_mono:.1f}")
    print(f"  (This is optimistic — mapping is fit TO the frequencies)")

    results["mono_sub"] = {
        "decrypted": dec_mono,
        "chi2": chi2_mono,
    }

    # ── 5. Bigram / Trigram analysis ────────────────────────────────
    print("\n" + "=" * 50)
    print("5. BIGRAM & TRIGRAM ANALYSIS")
    print("=" * 50)
    bigrams, rep_bi = bigram_analysis(PRE_ENE)
    trigrams, rep_tri = trigram_analysis(PRE_ENE)
    print(f"  Total bigrams: {len(bigrams)}")
    print(f"  Repeated bigrams: {rep_bi}")
    print(f"  Total trigrams: {len(trigrams)}")
    print(f"  Repeated trigrams: {rep_tri}")

    # Check for common English bigrams after Caesar shifts
    common_eng_bi = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND']
    print(f"\n  Common English bigram search across Caesar shifts:")
    for shift in range(MOD):
        dec = caesar_decrypt(PRE_ENE, shift)
        found = []
        for i in range(len(dec) - 1):
            bi = dec[i:i+2]
            if bi in common_eng_bi:
                found.append((i, bi))
        if len(found) >= 3:
            print(f"    shift={shift:2d}: {dec} | found {found}")

    results["ngrams"] = {
        "repeated_bigrams": rep_bi,
        "repeated_trigrams": rep_tri,
    }

    # ── 6. Comparison with post-ENE segments ────────────────────────
    print("\n" + "=" * 50)
    print("6. SEGMENT COMPARISON")
    print("=" * 50)
    # Break CT into segments of ~21 chars and compare IC
    for start in range(0, CT_LEN, 21):
        seg = CT[start:start+21]
        seg_ic = compute_ic(seg)
        seg_chi2 = compute_chi2(seg)
        print(f"  [{start:2d}-{start+len(seg)-1:2d}] ({len(seg):2d}ch) IC={seg_ic:.4f} chi²={seg_chi2:6.1f} : {seg}")

    results["segments"] = {}
    for start in range(0, CT_LEN, 21):
        seg = CT[start:start+21]
        results["segments"][f"{start}-{start+len(seg)-1}"] = {
            "ic": compute_ic(seg),
            "text": seg,
        }

    # ── 7. Is pre-ENE a "key indicator group"? ──────────────────────
    print("\n" + "=" * 50)
    print("7. KEY INDICATOR GROUP ANALYSIS")
    print("=" * 50)
    # In military ciphers, the first N chars sometimes encode the key setting
    # Check if pre-ENE maps to meaningful values

    # As indices: what are positions 0-20 in numeric form?
    pre_nums = [ALPH_IDX[c] for c in PRE_ENE]
    print(f"  As indices: {pre_nums}")

    # Mod 7 (period 7 — lag-7 signal!)
    mod7 = [x % 7 for x in pre_nums]
    print(f"  Mod 7: {mod7}")

    # As KRYPTOS alphabet
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    pre_ka = [ka_idx[c] for c in PRE_ENE]
    print(f"  KRYPTOS alphabet indices: {pre_ka}")
    print(f"  KRYPTOS mod 7: {[x % 7 for x in pre_ka]}")

    # Check if first 7 chars of pre-ENE could be a Vigenère key
    first7 = PRE_ENE[:7]
    print(f"\n  First 7 chars as key: {first7}")
    # Apply as Vigenère key to CT[21:] and see if cribs match
    ct_ene = CT[21:34]
    pt_ene = "EASTNORTHEAST"
    key7_indices = [ALPH_IDX[c] for c in first7]
    # Test: does applying first7 as period-7 Vigenère key decrypt CT?
    # KEY[p] = (CT[p] - PT[p]) mod 26 at crib positions
    # If first7 IS the key, then KEY[p%7] should equal key7_indices[p%7]
    matches = 0
    for p in range(21, 34):
        ct_val = ALPH_IDX[CT[p]]
        pt_val = ALPH_IDX[pt_ene[p-21]]
        derived_k = (ct_val - pt_val) % MOD
        expected_k = key7_indices[p % 7]
        if derived_k == expected_k:
            matches += 1
    print(f"  First 7 as Vig key for ENE crib: {matches}/13 matches")

    # Try ALL 7-char substrings of pre-ENE as period-7 key
    print(f"\n  All 7-char substrings of pre-ENE as period-7 Vig key:")
    best_sub_match = 0
    for start in range(15):  # 21 - 7 + 1 = 15
        key_sub = PRE_ENE[start:start+7]
        key_idx = [ALPH_IDX[c] for c in key_sub]
        m_ene = 0
        for p in range(21, 34):
            ct_val = ALPH_IDX[CT[p]]
            pt_val = ALPH_IDX[pt_ene[p-21]]
            derived_k = (ct_val - pt_val) % MOD
            expected_k = key_idx[p % 7]
            if derived_k == expected_k:
                m_ene += 1
        m_bc = 0
        pt_bc = "BERLINCLOCK"
        for p in range(63, 74):
            ct_val = ALPH_IDX[CT[p]]
            pt_val = ALPH_IDX[pt_bc[p-63]]
            derived_k = (ct_val - pt_val) % MOD
            expected_k = key_idx[p % 7]
            if derived_k == expected_k:
                m_bc += 1
        total = m_ene + m_bc
        if total >= 4:
            print(f"    [{start}:{start+7}] = {key_sub}: ENE={m_ene}/13 BC={m_bc}/11 total={total}/24")
        if total > best_sub_match:
            best_sub_match = total

    print(f"  Best substring match: {best_sub_match}/24 (expected ~0.9)")

    # Try as Beaufort key
    print(f"\n  All 7-char substrings as period-7 Beaufort key:")
    best_beau_match = 0
    for start in range(15):
        key_sub = PRE_ENE[start:start+7]
        key_idx = [ALPH_IDX[c] for c in key_sub]
        m_ene = 0
        for p in range(21, 34):
            ct_val = ALPH_IDX[CT[p]]
            pt_val = ALPH_IDX[pt_ene[p-21]]
            derived_k = (ct_val + pt_val) % MOD
            expected_k = key_idx[p % 7]
            if derived_k == expected_k:
                m_ene += 1
        m_bc = 0
        for p in range(63, 74):
            ct_val = ALPH_IDX[CT[p]]
            pt_val = ALPH_IDX[pt_bc[p-63]]
            derived_k = (ct_val + pt_val) % MOD
            expected_k = key_idx[p % 7]
            if derived_k == expected_k:
                m_bc += 1
        total = m_ene + m_bc
        if total >= 4:
            print(f"    [{start}:{start+7}] = {key_sub}: ENE={m_ene}/13 BC={m_bc}/11 total={total}/24")
        if total > best_beau_match:
            best_beau_match = total

    print(f"  Best Beaufort substring match: {best_beau_match}/24 (expected ~0.9)")

    results["key_indicator"] = {
        "first7_vig_match": matches,
        "best_substring_vig": best_sub_match,
        "best_substring_beau": best_beau_match,
    }

    # ── 8. Autocorrelation of pre-ENE ───────────────────────────────
    print("\n" + "=" * 50)
    print("8. AUTOCORRELATION")
    print("=" * 50)
    for lag in range(1, 11):
        matches_lag = sum(1 for i in range(len(PRE_ENE) - lag) if PRE_ENE[i] == PRE_ENE[i+lag])
        n_pairs = len(PRE_ENE) - lag
        expected = n_pairs / 26
        print(f"  Lag {lag:2d}: {matches_lag} matches in {n_pairs} pairs (expected {expected:.1f})")

    # ── 9. KA alphabet tests ────────────────────────────────────────
    print("\n" + "=" * 50)
    print("9. KRYPTOS ALPHABET DECRYPTION")
    print("=" * 50)
    # Try treating pre-ENE as KA-encoded (map through KRYPTOS alphabet)
    # KA: K=0, R=1, Y=2, P=3, T=4, O=5, S=6, A=7, B=8, C=9, D=10, E=11, F=12, G=13, H=14, I=15, J=16, L=17, M=18, N=19, Q=20, U=21, V=22, W=23, X=24, Z=25
    ka_to_std = {}
    for i, c in enumerate(KRYPTOS_ALPHABET):
        ka_to_std[c] = ALPH[i]  # Map position i in KA to position i in standard
    pre_ka_mapped = ''.join(ka_to_std[c] for c in PRE_ENE)
    print(f"  KA→Standard mapping: {pre_ka_mapped}")
    print(f"  IC of mapped: {compute_ic(pre_ka_mapped):.4f}")

    # Reverse KA
    pre_rka = ''.join(ALPH[25 - ka_idx[c]] for c in PRE_ENE)
    print(f"  Reverse KA mapping: {pre_rka}")

    # ── Summary ─────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Pre-ENE: {PRE_ENE}")
    print(f"  IC = {pre_ic:.4f} (English = 0.0667)")
    print(f"  P(random IC >= {pre_ic:.4f}): {pval:.4f}")
    print(f"  Chi² = {pre_chi2:.1f} (critical 37.65)")
    print(f"  Distinct letters: {len(pre_counts)}/26")
    print(f"  Key indicator test (best Vig): {best_sub_match}/24")
    print(f"  Key indicator test (best Beau): {best_beau_match}/24")

    if pval > 0.05:
        ic_verdict = "IC is NOT statistically significant (p > 0.05) — likely artifact of small sample + letter repetitions"
    else:
        ic_verdict = f"IC is statistically significant (p = {pval:.4f}) — warrants investigation"

    if pre_chi2 > 37.65:
        chi2_verdict = "Chi² rejects English at α=0.05 — frequency distribution is NOT English-like"
    else:
        chi2_verdict = "Chi² does not reject English at α=0.05 — frequency distribution is plausibly English-like"

    if best_sub_match <= 3 and best_beau_match <= 3:
        key_verdict = "Pre-ENE is NOT a period-7 key indicator group (scores at noise floor)"
    else:
        key_verdict = f"Pre-ENE shows weak key indicator signal: Vig={best_sub_match}/24, Beau={best_beau_match}/24"

    print(f"\n  IC verdict: {ic_verdict}")
    print(f"  Chi² verdict: {chi2_verdict}")
    print(f"  Key indicator verdict: {key_verdict}")

    overall_verdict = "NO SIGNAL" if pval > 0.05 and pre_chi2 > 37.65 else "WEAK SIGNAL — investigate further"
    print(f"\n  Overall: {overall_verdict}")
    print(f"  Time: {elapsed:.1f}s")

    results["verdict"] = overall_verdict
    results["ic_verdict"] = ic_verdict
    results["chi2_verdict"] = chi2_verdict
    results["key_indicator_verdict"] = key_verdict
    results["elapsed_seconds"] = elapsed

    with open("results/e_s_54_pre_ene.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n  Artifact: results/e_s_54_pre_ene.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_54_pre_ene_analysis.py")


if __name__ == "__main__":
    main()
