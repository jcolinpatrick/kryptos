#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-19: Pre-ENE Segment Deep Analysis (RQ-7)

Positions 0-20 of K4 have IC = 0.067, which is English-like. This experiment
investigates whether this segment is encrypted differently from the rest of K4.

Analysis:
1. Calibrate: What's the IC distribution for 21-char random vs English text?
   Is 0.067 actually unusual?
2. Segment analysis: IC, frequency, bigram/trigram stats for 5 segments:
   - Pre-ENE (0-20), ENE crib (21-33), gap (34-62), BC crib (63-73), post-BC (74-96)
3. Monoalphabetic decryption attempt on pre-ENE segment
4. Low-period Vigenere/Beaufort on pre-ENE segment using known key structure
5. Test if pre-ENE frequency distribution matches shifted English
6. Cross-correlation between segments

Key question: Is the pre-ENE IC actually significant, or is it just noise
at n=21? If significant, what cipher model best explains it?
"""

import json
import math
import os
import random
import time
from collections import Counter

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD, ALPH_IDX, CRIB_DICT,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    IC_ENGLISH, IC_RANDOM,
)


def compute_ic(text: str) -> float:
    """Compute index of coincidence for a string."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def compute_bigrams(text: str) -> Counter:
    """Count bigrams in text."""
    return Counter(text[i:i+2] for i in range(len(text) - 1))


def compute_trigrams(text: str) -> Counter:
    """Count trigrams in text."""
    return Counter(text[i:i+3] for i in range(len(text) - 2))


def chi_squared_uniform(text: str) -> tuple:
    """Chi-squared test against uniform distribution. Returns (chi2, dof)."""
    n = len(text)
    expected = n / 26.0
    counts = Counter(text)
    chi2 = sum((counts.get(c, 0) - expected) ** 2 / expected for c in ALPH)
    return chi2, 25  # 26 - 1 degrees of freedom


def entropy(text: str) -> float:
    """Shannon entropy of character distribution."""
    n = len(text)
    counts = Counter(text)
    return -sum((c/n) * math.log2(c/n) for c in counts.values() if c > 0)


def generate_random_text(length: int) -> str:
    """Generate random text of given length."""
    return ''.join(random.choice(ALPH) for _ in range(length))


ENGLISH_FREQ = {
    'A': 0.0817, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}


def generate_english_like(length: int) -> str:
    """Generate text with English letter frequencies."""
    letters = list(ENGLISH_FREQ.keys())
    weights = list(ENGLISH_FREQ.values())
    return ''.join(random.choices(letters, weights=weights, k=length))


def frequency_correlation(text: str) -> float:
    """Correlation between text frequency and English frequency."""
    n = len(text)
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


def try_caesar(text: str, shift: int) -> str:
    """Apply Caesar shift to text."""
    return ''.join(ALPH[(ALPH_IDX[c] + shift) % MOD] for c in text)


def main():
    t0 = time.time()
    random.seed(42)

    print("=" * 70)
    print("E-FRAC-19: Pre-ENE Segment Deep Analysis (RQ-7)")
    print("=" * 70)

    results = {}

    # Define segments
    segments = {
        'pre_ene': (0, 21),    # 21 chars
        'ene': (21, 34),       # 13 chars (ENE crib)
        'gap': (34, 63),       # 29 chars
        'bc': (63, 74),        # 11 chars (BC crib)
        'post_bc': (74, 97),   # 23 chars
        'full': (0, 97),       # 97 chars
    }

    seg_texts = {name: CT[start:end] for name, (start, end) in segments.items()}

    # ── Section 1: Segment statistics ────────────────────────────────────
    print("\n--- Section 1: Segment Statistics ---")
    print(f"{'Segment':<10} {'Len':>3} {'IC':>6} {'Entropy':>7} {'Chi2':>6} {'FreqCorr':>8} {'Unique':>6}")
    print("-" * 55)

    seg_stats = {}
    for name, text in seg_texts.items():
        ic = compute_ic(text)
        ent = entropy(text)
        chi2, dof = chi_squared_uniform(text)
        fcorr = frequency_correlation(text)
        unique = len(set(text))

        seg_stats[name] = {
            'length': len(text),
            'ic': ic,
            'entropy': ent,
            'chi2': chi2,
            'freq_correlation': fcorr,
            'unique_chars': unique,
            'text': text,
        }
        print(f"{name:<10} {len(text):>3} {ic:>6.4f} {ent:>7.3f} {chi2:>6.1f} {fcorr:>8.3f} {unique:>6}")

    results['segment_stats'] = seg_stats

    # ── Section 2: IC calibration for 21-char text ───────────────────────
    print("\n--- Section 2: IC Calibration for n=21 ---")
    print("  How unusual is IC=0.067 for a 21-character sample?")

    n_sims = 100000
    pre_ene_ic = seg_stats['pre_ene']['ic']

    # Random 21-char text IC distribution
    random_ics = []
    for _ in range(n_sims):
        txt = generate_random_text(21)
        random_ics.append(compute_ic(txt))
    random_ics.sort()

    pctile_random = sum(1 for ic in random_ics if ic <= pre_ene_ic) / n_sims * 100
    mean_random = sum(random_ics) / len(random_ics)
    std_random = math.sqrt(sum((ic - mean_random) ** 2 for ic in random_ics) / len(random_ics))
    z_random = (pre_ene_ic - mean_random) / std_random if std_random > 0 else 0

    print(f"  Pre-ENE IC: {pre_ene_ic:.4f}")
    print(f"  Random 21-char: mean={mean_random:.4f}, std={std_random:.4f}")
    print(f"  Percentile in random: {pctile_random:.1f}%")
    print(f"  Z-score vs random: {z_random:.2f}")

    # English 21-char text IC distribution
    english_ics = []
    for _ in range(n_sims):
        txt = generate_english_like(21)
        english_ics.append(compute_ic(txt))
    english_ics.sort()

    pctile_english = sum(1 for ic in english_ics if ic <= pre_ene_ic) / n_sims * 100
    mean_english = sum(english_ics) / len(english_ics)
    std_english = math.sqrt(sum((ic - mean_english) ** 2 for ic in english_ics) / len(english_ics))
    z_english = (pre_ene_ic - mean_english) / std_english if std_english > 0 else 0

    print(f"  English 21-char: mean={mean_english:.4f}, std={std_english:.4f}")
    print(f"  Percentile in English: {pctile_english:.1f}%")
    print(f"  Z-score vs English: {z_english:.2f}")

    # Vigenere-encrypted English IC distribution (periods 3-7)
    print(f"\n  Vigenere-encrypted English IC distribution (n=21):")
    vig_results = {}
    for period in range(3, 8):
        vig_ics = []
        for _ in range(n_sims):
            pt = generate_english_like(21)
            key = [random.randint(0, 25) for _ in range(period)]
            ct = ''.join(ALPH[(ALPH_IDX[c] + key[i % period]) % MOD] for i, c in enumerate(pt))
            vig_ics.append(compute_ic(ct))
        vig_ics.sort()
        pctile = sum(1 for ic in vig_ics if ic <= pre_ene_ic) / n_sims * 100
        mean_v = sum(vig_ics) / len(vig_ics)
        vig_results[period] = {'mean': mean_v, 'percentile': pctile}
        print(f"    Period {period}: mean IC={mean_v:.4f}, pre-ENE at {pctile:.1f}th percentile")

    results['ic_calibration'] = {
        'pre_ene_ic': pre_ene_ic,
        'random_21': {'mean': mean_random, 'std': std_random, 'percentile': pctile_random, 'z': z_random},
        'english_21': {'mean': mean_english, 'std': std_english, 'percentile': pctile_english, 'z': z_english},
        'vigenere_encrypted': vig_results,
    }

    # ── Section 3: IC calibration for ALL segments ───────────────────────
    print("\n--- Section 3: IC calibration for all segments ---")

    cal_results = {}
    for name, text in seg_texts.items():
        n = len(text)
        if n < 5:
            continue
        seg_ic = compute_ic(text)

        rnd_ics = []
        for _ in range(50000):
            rnd_ics.append(compute_ic(generate_random_text(n)))
        rnd_ics.sort()
        pctile = sum(1 for ic in rnd_ics if ic <= seg_ic) / len(rnd_ics) * 100
        mean_r = sum(rnd_ics) / len(rnd_ics)
        std_r = math.sqrt(sum((ic - mean_r) ** 2 for ic in rnd_ics) / len(rnd_ics))

        eng_ics = []
        for _ in range(50000):
            eng_ics.append(compute_ic(generate_english_like(n)))
        eng_ics.sort()
        pctile_e = sum(1 for ic in eng_ics if ic <= seg_ic) / len(eng_ics) * 100
        mean_e = sum(eng_ics) / len(eng_ics)

        cal_results[name] = {
            'ic': seg_ic, 'length': n,
            'random_pctile': pctile, 'random_mean': mean_r,
            'english_pctile': pctile_e, 'english_mean': mean_e,
        }
        print(f"  {name:<10} (n={n:2d}): IC={seg_ic:.4f}, "
              f"random pctile={pctile:.1f}%, english pctile={pctile_e:.1f}%")

    results['all_segments_ic'] = cal_results

    # ── Section 4: Pre-ENE frequency analysis ────────────────────────────
    print("\n--- Section 4: Pre-ENE letter frequency analysis ---")
    pre_ene_text = seg_texts['pre_ene']
    print(f"  Pre-ENE text: {pre_ene_text}")

    # Letter frequencies
    counts = Counter(pre_ene_text)
    print(f"\n  Letter frequencies (sorted by count):")
    for ch, cnt in counts.most_common():
        eng_rank = sorted(ENGLISH_FREQ.items(), key=lambda x: -x[1])
        eng_pos = [c for c, _ in eng_rank].index(ch) + 1
        print(f"    {ch}: {cnt} ({cnt/21:.3f}) — English rank #{eng_pos} (freq={ENGLISH_FREQ[ch]:.4f})")

    # Missing letters
    missing = set(ALPH) - set(pre_ene_text)
    print(f"\n  Missing letters ({len(missing)}): {sorted(missing)}")
    print(f"  Unique letters: {len(set(pre_ene_text))}/26")

    # ── Section 5: Caesar shift analysis on pre-ENE ──────────────────────
    print("\n--- Section 5: Caesar shift analysis on pre-ENE ---")
    print("  Testing all 26 Caesar shifts for English-like frequency:")

    caesar_results = []
    for shift in range(26):
        shifted = try_caesar(pre_ene_text, shift)
        fcorr = frequency_correlation(shifted)
        ic = compute_ic(shifted)  # IC is invariant under Caesar, just for verification
        caesar_results.append({
            'shift': shift,
            'shift_letter': ALPH[shift],
            'text': shifted,
            'freq_correlation': fcorr,
            'ic': ic,
        })

    caesar_results.sort(key=lambda x: x['freq_correlation'], reverse=True)
    print(f"  Top 5 Caesar shifts by English frequency correlation:")
    for entry in caesar_results[:5]:
        print(f"    Shift {entry['shift']:2d} ({entry['shift_letter']}): "
              f"corr={entry['freq_correlation']:.3f}, text={entry['text']}")

    results['caesar_analysis'] = [
        {k: v for k, v in e.items()} for e in caesar_results[:10]
    ]

    # ── Section 6: Monoalphabetic best-fit for pre-ENE ───────────────────
    print("\n--- Section 6: Monoalphabetic frequency matching ---")
    print("  Matching pre-ENE frequencies to English by rank:")

    # Rank-based substitution
    pre_ene_ranked = [c for c, _ in Counter(pre_ene_text).most_common()]
    eng_ranked = [c for c, _ in sorted(ENGLISH_FREQ.items(), key=lambda x: -x[1])]

    # Build substitution by frequency rank
    sub_map = {}
    for ct_char, pt_char in zip(pre_ene_ranked, eng_ranked):
        sub_map[ct_char] = pt_char
    # Map remaining
    remaining_ct = [c for c in ALPH if c not in sub_map]
    remaining_pt = [c for c in eng_ranked if c not in sub_map.values()]
    for ct_char, pt_char in zip(remaining_ct, remaining_pt):
        sub_map[ct_char] = pt_char

    mono_decrypt = ''.join(sub_map[c] for c in pre_ene_text)
    print(f"  Frequency-rank decryption: {mono_decrypt}")
    results['mono_decrypt'] = mono_decrypt

    # ── Section 7: Bigram and trigram analysis ────────────────────────────
    print("\n--- Section 7: N-gram analysis ---")

    for name in ['pre_ene', 'gap', 'post_bc', 'full']:
        text = seg_texts[name]
        bigs = compute_bigrams(text)
        trigs = compute_trigrams(text)
        repeated_bigs = {k: v for k, v in bigs.items() if v > 1}
        repeated_trigs = {k: v for k, v in trigs.items() if v > 1}

        print(f"  {name} ({len(text)} chars):")
        print(f"    Repeated bigrams: {len(repeated_bigs)} — {dict(sorted(repeated_bigs.items(), key=lambda x: -x[1]))}")
        print(f"    Repeated trigrams: {len(repeated_trigs)} — {dict(sorted(repeated_trigs.items(), key=lambda x: -x[1]))}")

    # ── Section 8: Cross-segment key continuity ──────────────────────────
    print("\n--- Section 8: Key continuity across segments ---")
    print("  If the cipher changes at position 21, the key pattern should change too.")
    print("  Testing: do key values at ENE positions 'continue' a pattern from pre-ENE?")

    # For Beaufort (our best lead), show key values at positions 0-33
    for variant in ['beaufort', 'vigenere']:
        print(f"\n  {variant.upper()} key values at crib positions:")
        key_line = []
        for pos in sorted(CRIB_DICT.keys()):
            k = (ALPH_IDX[CT[pos]] + ALPH_IDX[CRIB_DICT[pos]]) % MOD if variant == 'beaufort' else \
                (ALPH_IDX[CT[pos]] - ALPH_IDX[CRIB_DICT[pos]]) % MOD
            key_line.append((pos, k))
            print(f"    pos {pos:2d}: CT={CT[pos]}, PT={CRIB_DICT[pos]}, key={k:2d} ({ALPH[k]})")

    # ── Section 9: Pre-ENE as potential key indicator ────────────────────
    print("\n--- Section 9: Pre-ENE as potential cipher indicator group ---")
    print("  In classical cryptography, the first few characters sometimes encode")
    print("  the key or indicator for the rest of the message.")

    # What if pre-ENE characters ARE the key for the rest?
    pre_ene_vals = [ALPH_IDX[c] for c in pre_ene_text]
    print(f"  Pre-ENE as key values: {pre_ene_vals}")
    print(f"  Pre-ENE text: {pre_ene_text}")

    # Test: use pre-ENE characters as repeating key for positions 21-96
    print(f"\n  Testing pre-ENE as repeating key (period {len(pre_ene_text)}):")
    for variant in ['vigenere', 'beaufort']:
        matches = 0
        for pos in sorted(CRIB_DICT.keys()):
            key_idx = (pos - 21) % len(pre_ene_text)
            key_val = pre_ene_vals[key_idx]

            ct_val = ALPH_IDX[CT[pos]]
            if variant == 'vigenere':
                pt_val = (ct_val - key_val) % MOD
            else:
                pt_val = (key_val - ct_val) % MOD

            expected = ALPH_IDX[CRIB_DICT[pos]]
            if pt_val == expected:
                matches += 1

        print(f"    {variant}: {matches}/24 crib matches")

    # Test: use pre-ENE as running key starting from position 0
    print(f"\n  Testing pre-ENE as running key from pos 0:")
    for variant in ['vigenere', 'beaufort']:
        matches = 0
        for pos in sorted(CRIB_DICT.keys()):
            if pos < len(pre_ene_text):
                key_val = pre_ene_vals[pos]
            else:
                continue  # Not enough key material
            ct_val = ALPH_IDX[CT[pos]]
            if variant == 'vigenere':
                pt_val = (ct_val - key_val) % MOD
            else:
                pt_val = (key_val - ct_val) % MOD
            expected = ALPH_IDX[CRIB_DICT[pos]]
            if pt_val == expected:
                matches += 1
        # Only counts positions 21-20 which is 0 positions in pre-ENE
        # Need to extend: use the first 21 chars as key for pos 0-20, then extend
        print(f"    {variant}: {matches} matches (only pos 21-33 testable)")

    # ── Section 10: Statistical significance of pre-ENE IC ───────────────
    print("\n--- Section 10: Is pre-ENE IC actually significant? ---")

    # Test all possible contiguous 21-char segments of K4
    print("  IC for all contiguous 21-char segments of K4:")
    segment_ics = []
    for start in range(CT_LEN - 20):
        seg = CT[start:start+21]
        seg_ic = compute_ic(seg)
        segment_ics.append((start, seg_ic))

    segment_ics.sort(key=lambda x: -x[1])
    print(f"  Top 5 highest IC (21-char segments):")
    for start, ic_val in segment_ics[:5]:
        print(f"    pos {start:2d}-{start+20:2d}: IC={ic_val:.4f} — {CT[start:start+21]}")
    print(f"  Bottom 5 lowest IC:")
    for start, ic_val in segment_ics[-5:]:
        print(f"    pos {start:2d}-{start+20:2d}: IC={ic_val:.4f} — {CT[start:start+21]}")

    # What's the rank of position 0-20?
    rank_0_20 = None
    for i, (start, _) in enumerate(segment_ics):
        if start == 0:
            rank_0_20 = i + 1
            break

    print(f"\n  Pre-ENE (pos 0-20) rank: #{rank_0_20} out of {CT_LEN - 20} segments")
    print(f"  Is it the highest? {'YES' if rank_0_20 == 1 else 'NO'}")

    # How many 21-char segments have IC >= 0.067?
    n_above = sum(1 for _, ic_val in segment_ics if ic_val >= pre_ene_ic)
    print(f"  Segments with IC >= {pre_ene_ic:.4f}: {n_above}/{CT_LEN - 20}")

    # Multiple testing: if we check all 77 segments, finding one with IC=0.067
    # is less surprising than if we only checked position 0-20
    p_single = 1 - pctile_random / 100  # p-value for single test
    p_corrected = min(1.0, p_single * (CT_LEN - 20))  # Bonferroni
    print(f"  Single-test p-value: {p_single:.4f}")
    print(f"  Bonferroni-corrected (77 tests): {p_corrected:.4f}")

    results['pre_ene_significance'] = {
        'rank': rank_0_20,
        'n_segments': CT_LEN - 20,
        'n_above_threshold': n_above,
        'p_single': p_single,
        'p_corrected': p_corrected,
    }

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Pre-ENE (pos 0-20): IC={pre_ene_ic:.4f}")
    print(f"  Percentile in random 21-char: {pctile_random:.1f}%")
    print(f"  Percentile in English 21-char: {pctile_english:.1f}%")
    print(f"  Rank among all 21-char K4 segments: #{rank_0_20}/{CT_LEN - 20}")
    print(f"  Bonferroni-corrected p-value: {p_corrected:.4f}")

    if p_corrected < 0.05:
        verdict = "SIGNIFICANT"
        print(f"  Verdict: {verdict} — pre-ENE IC is unusually high even after correction")
    elif pctile_random > 90:
        verdict = "MARGINALLY_INTERESTING"
        print(f"  Verdict: {verdict} — high IC but does not survive multiple testing")
    else:
        verdict = "NOISE"
        print(f"  Verdict: {verdict} — pre-ENE IC is within normal range for n=21")

    print(f"  Runtime: {elapsed:.1f}s")
    print(f"\nRESULT: ic={pre_ene_ic:.4f} pctile_random={pctile_random:.1f} "
          f"pctile_english={pctile_english:.1f} verdict={verdict}")

    # Save results
    os.makedirs("results/frac", exist_ok=True)
    output = {
        'experiment': 'E-FRAC-19',
        'description': 'Pre-ENE segment deep analysis (RQ-7)',
        'segment_stats': {k: {kk: vv for kk, vv in v.items() if kk != 'text'}
                          for k, v in seg_stats.items()},
        'ic_calibration': results.get('ic_calibration', {}),
        'all_segments_ic': cal_results,
        'pre_ene_significance': results.get('pre_ene_significance', {}),
        'caesar_top5': results.get('caesar_analysis', [])[:5],
        'mono_decrypt': mono_decrypt,
        'verdict': verdict,
        'runtime': elapsed,
    }
    with open("results/frac/e_frac_19_pre_ene_analysis.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"  Results written to results/frac/e_frac_19_pre_ene_analysis.json")


if __name__ == "__main__":
    main()
