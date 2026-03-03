#!/usr/bin/env python3
"""E-ATBASH-02: Statistical analysis of Atbash-transformed K4 ciphertext.

Hypothesis: The carved K4 text was Atbash-encoded, so the REAL ciphertext
is the Atbash of the carved text.

Analyses:
1. Verify Atbash computation from original CT
2. Letter frequency comparison (original CT, Atbash CT, English)
3. Index of Coincidence for both
4. Repeated bigrams/trigrams in Atbash CT
5. Kasiski-like repeats (repeated n-grams with spacing analysis)
6. Atbash of crib letters individually
7. Common English trigram frequency comparison
8. Autokey decryption with seeds KRYPTOS, PALIMPSEST, ABSCISSA
"""

from __future__ import annotations

import json
import os
from collections import Counter
from math import gcd
from typing import Dict, List, Tuple

from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, CT, CT_LEN, CRIB_WORDS, MOD,
)

# ── Helpers ──────────────────────────────────────────────────────────────────

def atbash(text: str) -> str:
    """Apply Atbash cipher: A<->Z, B<->Y, C<->X, ..."""
    return "".join(ALPH[25 - ALPH_IDX[c]] for c in text)


def ic(text: str) -> float:
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def letter_freq(text: str) -> Dict[str, float]:
    """Letter frequency as proportions."""
    n = len(text)
    counts = Counter(text)
    return {c: counts.get(c, 0) / n for c in ALPH}


def vigenere_decrypt(ct: str, key: str) -> str:
    """Vigenere decryption: PT[i] = (CT[i] - KEY[i]) mod 26."""
    kl = len(key)
    return "".join(
        ALPH[(ALPH_IDX[ct[i]] - ALPH_IDX[key[i % kl]]) % 26]
        for i in range(len(ct))
    )


def beaufort_decrypt(ct: str, key: str) -> str:
    """Beaufort decryption: PT[i] = (KEY[i] - CT[i]) mod 26."""
    kl = len(key)
    return "".join(
        ALPH[(ALPH_IDX[key[i % kl]] - ALPH_IDX[ct[i]]) % 26]
        for i in range(len(ct))
    )


def autokey_decrypt_vig(ct: str, seed: str) -> str:
    """Autokey Vigenere: key extends with plaintext.
    PT[i] = (CT[i] - K[i]) mod 26, where K = seed || PT[0] || PT[1] || ...
    """
    pt = []
    key_stream = list(seed)
    for i in range(len(ct)):
        k = ALPH_IDX[key_stream[i]]
        p = (ALPH_IDX[ct[i]] - k) % 26
        pt.append(ALPH[p])
        key_stream.append(ALPH[p])
    return "".join(pt)


def autokey_decrypt_beaufort(ct: str, seed: str) -> str:
    """Autokey Beaufort: key extends with plaintext.
    PT[i] = (K[i] - CT[i]) mod 26, where K = seed || PT[0] || PT[1] || ...
    """
    pt = []
    key_stream = list(seed)
    for i in range(len(ct)):
        k = ALPH_IDX[key_stream[i]]
        p = (k - ALPH_IDX[ct[i]]) % 26
        pt.append(ALPH[p])
        key_stream.append(ALPH[p])
    return "".join(pt)


def autokey_ct_decrypt_vig(ct: str, seed: str) -> str:
    """Autokey Vigenere with CT extension (key = seed || CT).
    PT[i] = (CT[i] - K[i]) mod 26, where K = seed || CT[0] || CT[1] || ...
    """
    key_stream = list(seed) + list(ct)
    return "".join(
        ALPH[(ALPH_IDX[ct[i]] - ALPH_IDX[key_stream[i]]) % 26]
        for i in range(len(ct))
    )


def quadgram_score(text: str, qg: Dict[str, float]) -> float:
    """Average log10 quadgram probability per character."""
    if len(text) < 4:
        return -10.0
    floor = min(qg.values()) - 1.0
    total = sum(qg.get(text[i:i+4], floor) for i in range(len(text) - 3))
    return total / len(text)


def find_repeated_ngrams(text: str, min_n: int = 2, max_n: int = 6) -> Dict[str, List[int]]:
    """Find all repeated n-grams and their starting positions."""
    results = {}
    for n in range(min_n, max_n + 1):
        seen: Dict[str, List[int]] = {}
        for i in range(len(text) - n + 1):
            ng = text[i:i+n]
            if ng not in seen:
                seen[ng] = []
            seen[ng].append(i)
        for ng, positions in seen.items():
            if len(positions) > 1:
                results[ng] = positions
    return results


# English letter frequencies (approximate)
ENGLISH_FREQ = {
    'A': 0.0817, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}

COMMON_TRIGRAMS = [
    "THE", "AND", "ING", "HER", "HAT", "HIS", "THA", "ERE", "FOR",
    "ENT", "ION", "TER", "WAS", "YOU", "ITH", "VER", "ALL", "WIT",
    "THI", "TIO", "NOT", "ARE", "BUT", "HAD", "ONE", "OUR", "OUT",
]


def main() -> None:
    print("=" * 72)
    print("E-ATBASH-02: Atbash K4 Statistical Analysis")
    print("=" * 72)

    # ── 1. Verify Atbash ────────────────────────────────────────────────
    print("\n[1] VERIFY ATBASH COMPUTATION")
    print(f"  Original CT ({len(CT)} chars): {CT}")
    atbash_ct = atbash(CT)
    print(f"  Atbash CT   ({len(atbash_ct)} chars): {atbash_ct}")
    assert len(atbash_ct) == CT_LEN, f"Length mismatch: {len(atbash_ct)} != {CT_LEN}"

    # Verify roundtrip
    roundtrip = atbash(atbash_ct)
    assert roundtrip == CT, "Atbash roundtrip FAILED"
    print("  Roundtrip verification: PASS")

    # Check user-provided Atbash
    user_atbash = "LYPIFLCLTSFOYHLORUYYDUOIEJJKIMTPHHLGDGJHQJHHVPAADZGQPOFWRZDRMUYMBKEGGNAUKPDTWPACGQXWRTPFSFZFVPXZI"
    if atbash_ct == user_atbash:
        print("  User-provided Atbash: MATCHES computed Atbash")
    else:
        print("  User-provided Atbash: MISMATCH!")
        print(f"    User:     {user_atbash}")
        print(f"    Computed: {atbash_ct}")
        for i in range(min(len(user_atbash), len(atbash_ct))):
            if user_atbash[i] != atbash_ct[i]:
                print(f"    First diff at pos {i}: user='{user_atbash[i]}' computed='{atbash_ct[i]}'")
                break

    # ── 2. Letter Frequency Comparison ──────────────────────────────────
    print("\n[2] LETTER FREQUENCY COMPARISON")
    freq_orig = letter_freq(CT)
    freq_atb = letter_freq(atbash_ct)

    print(f"  {'Letter':>6} {'Orig%':>7} {'Atbash%':>8} {'English%':>9} {'Orig#':>6} {'Atb#':>6}")
    print(f"  {'-'*6:>6} {'-'*7:>7} {'-'*8:>8} {'-'*9:>9} {'-'*6:>6} {'-'*6:>6}")
    orig_counts = Counter(CT)
    atb_counts = Counter(atbash_ct)
    for c in ALPH:
        print(f"  {c:>6} {freq_orig.get(c,0)*100:>7.2f} {freq_atb.get(c,0)*100:>8.2f}"
              f" {ENGLISH_FREQ[c]*100:>9.2f} {orig_counts.get(c,0):>6} {atb_counts.get(c,0):>6}")

    # Chi-squared distance from English
    chi2_orig = sum((freq_orig.get(c,0) - ENGLISH_FREQ[c])**2 / ENGLISH_FREQ[c]
                     for c in ALPH)
    chi2_atb = sum((freq_atb.get(c,0) - ENGLISH_FREQ[c])**2 / ENGLISH_FREQ[c]
                    for c in ALPH)
    print(f"\n  Chi-squared distance from English:")
    print(f"    Original CT: {chi2_orig:.4f}")
    print(f"    Atbash CT:   {chi2_atb:.4f}")
    print(f"    (Lower = closer to English)")

    # ── 3. Index of Coincidence ─────────────────────────────────────────
    print("\n[3] INDEX OF COINCIDENCE")
    ic_orig = ic(CT)
    ic_atb = ic(atbash_ct)
    print(f"  Original CT IC: {ic_orig:.6f}")
    print(f"  Atbash CT IC:   {ic_atb:.6f}")
    print(f"  English IC:     0.066700")
    print(f"  Random IC:      0.038462")
    print(f"  NOTE: Atbash is a monoalphabetic substitution, so IC is preserved.")
    assert abs(ic_orig - ic_atb) < 1e-10, "IC should be identical under Atbash!"
    print(f"  Verified: IC is identical (difference = {abs(ic_orig - ic_atb):.2e})")

    # ── 4. Repeated bigrams/trigrams in Atbash CT ───────────────────────
    print("\n[4] REPEATED BIGRAMS/TRIGRAMS IN ATBASH CT")
    repeats_atb = find_repeated_ngrams(atbash_ct, 2, 6)
    repeats_orig = find_repeated_ngrams(CT, 2, 6)

    for label, repeats, text in [("ORIGINAL CT", repeats_orig, CT),
                                  ("ATBASH CT", repeats_atb, atbash_ct)]:
        print(f"\n  {label}:")
        for n in range(2, 7):
            ngrams = {k: v for k, v in repeats.items() if len(k) == n}
            if ngrams:
                # Sort by count descending
                sorted_ng = sorted(ngrams.items(), key=lambda x: -len(x[1]))
                shown = 0
                for ng, positions in sorted_ng:
                    if shown >= 10:
                        remaining = len(sorted_ng) - shown
                        if remaining > 0:
                            print(f"    ... and {remaining} more {n}-grams")
                        break
                    spacings = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
                    print(f"    {ng}: count={len(positions)}, "
                          f"positions={positions}, spacings={spacings}")
                    shown += 1
            else:
                print(f"    No repeated {n}-grams")

    # ── 5. Kasiski-like analysis (factor spacings) ──────────────────────
    print("\n[5] KASISKI-LIKE ANALYSIS (spacing factors)")
    for label, repeats in [("ORIGINAL CT", repeats_orig), ("ATBASH CT", repeats_atb)]:
        print(f"\n  {label}:")
        all_spacings = []
        for ng, positions in repeats.items():
            if len(ng) >= 3:  # Only trigrams and above for Kasiski
                for i in range(len(positions)):
                    for j in range(i+1, len(positions)):
                        all_spacings.append(positions[j] - positions[i])

        if all_spacings:
            factor_counts: Counter = Counter()
            for s in all_spacings:
                for f in range(2, s + 1):
                    if s % f == 0:
                        factor_counts[f] += 1
            print(f"    Total spacings from 3+-grams: {len(all_spacings)}")
            print(f"    Top 15 factors:")
            for factor, count in factor_counts.most_common(15):
                print(f"      Factor {factor:>3}: {count} occurrences")
        else:
            print("    No repeated 3+-grams found for Kasiski analysis")

    # ── 6. Atbash of crib letters ───────────────────────────────────────
    print("\n[6] ATBASH OF CRIB LETTERS")
    for start, word in CRIB_WORDS:
        atbash_word = atbash(word)
        print(f"  {word} (pos {start}-{start+len(word)-1})")
        print(f"    Atbash: {atbash_word}")
        # Show letter-by-letter
        for i, (p, a) in enumerate(zip(word, atbash_word)):
            pos = start + i
            ct_at_pos = CT[pos]
            atb_ct_at_pos = atbash_ct[pos]
            print(f"    pos {pos:>2}: PT='{p}' -> Atbash='{a}' | "
                  f"CarvedCT='{ct_at_pos}' -> AtbashCT='{atb_ct_at_pos}'")

    # Check if Atbash cribs appear anywhere in Atbash CT
    print("\n  Searching for Atbash cribs in Atbash CT:")
    for start, word in CRIB_WORDS:
        atbash_word = atbash(word)
        found = []
        for i in range(len(atbash_ct) - len(atbash_word) + 1):
            if atbash_ct[i:i+len(atbash_word)] == atbash_word:
                found.append(i)
        if found:
            print(f"    '{atbash_word}' found at positions: {found}")
        else:
            print(f"    '{atbash_word}' NOT found in Atbash CT")

    # ── 7. Common English trigram comparison ────────────────────────────
    print("\n[7] COMMON ENGLISH TRIGRAM FREQUENCY")
    print(f"  {'Trigram':>8} {'Orig#':>6} {'Atbash#':>7}")
    print(f"  {'-'*8:>8} {'-'*6:>6} {'-'*7:>7}")
    orig_tri_total = 0
    atb_tri_total = 0
    for tri in COMMON_TRIGRAMS:
        count_orig = sum(1 for i in range(len(CT) - 2) if CT[i:i+3] == tri)
        count_atb = sum(1 for i in range(len(atbash_ct) - 2) if atbash_ct[i:i+3] == tri)
        orig_tri_total += count_orig
        atb_tri_total += count_atb
        if count_orig > 0 or count_atb > 0:
            print(f"  {tri:>8} {count_orig:>6} {count_atb:>7}")
    print(f"  {'TOTAL':>8} {orig_tri_total:>6} {atb_tri_total:>7}")

    # Also check all trigrams that appear in each
    print(f"\n  All trigrams appearing 2+ times:")
    for label, text in [("ORIGINAL", CT), ("ATBASH", atbash_ct)]:
        tri_counter: Counter = Counter()
        for i in range(len(text) - 2):
            tri_counter[text[i:i+3]] += 1
        repeating = {k: v for k, v in tri_counter.items() if v >= 2}
        if repeating:
            print(f"    {label}: {dict(sorted(repeating.items(), key=lambda x: -x[1]))}")
        else:
            print(f"    {label}: none")

    # ── 8. Autokey decryptions ──────────────────────────────────────────
    print("\n[8] AUTOKEY DECRYPTION OF ATBASH CT")
    seeds = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]

    # Try to load quadgrams for scoring
    qg_path = os.path.join(os.path.dirname(__file__), "..", "data", "english_quadgrams.json")
    qg_path = os.path.normpath(qg_path)
    qg = None
    if os.path.exists(qg_path):
        with open(qg_path) as f:
            qg = json.load(f)
        print(f"  Loaded quadgrams from {qg_path}")
    else:
        print(f"  Quadgrams not found at {qg_path}, skipping qg scoring")

    for seed in seeds:
        print(f"\n  Seed: {seed}")

        # PT-autokey Vigenere
        pt_avig = autokey_decrypt_vig(atbash_ct, seed)
        qg_score_avig = quadgram_score(pt_avig, qg) if qg else "N/A"
        print(f"    Autokey-Vig (PT ext):     {pt_avig}")
        print(f"      IC={ic(pt_avig):.6f}, qg={qg_score_avig}")

        # PT-autokey Beaufort
        pt_abeau = autokey_decrypt_beaufort(atbash_ct, seed)
        qg_score_abeau = quadgram_score(pt_abeau, qg) if qg else "N/A"
        print(f"    Autokey-Beau (PT ext):    {pt_abeau}")
        print(f"      IC={ic(pt_abeau):.6f}, qg={qg_score_abeau}")

        # CT-autokey Vigenere
        ct_avig = autokey_ct_decrypt_vig(atbash_ct, seed)
        qg_score_ctvig = quadgram_score(ct_avig, qg) if qg else "N/A"
        print(f"    Autokey-Vig (CT ext):     {ct_avig}")
        print(f"      IC={ic(ct_avig):.6f}, qg={qg_score_ctvig}")

    # Also try simple periodic Vigenere and Beaufort on Atbash CT
    print("\n  PERIODIC VIG/BEAU ON ATBASH CT (for reference):")
    for seed in seeds:
        pt_vig = vigenere_decrypt(atbash_ct, seed)
        pt_beau = beaufort_decrypt(atbash_ct, seed)
        qg_vig = quadgram_score(pt_vig, qg) if qg else "N/A"
        qg_beau = quadgram_score(pt_beau, qg) if qg else "N/A"
        print(f"    Vig/{seed}: {pt_vig[:50]}... IC={ic(pt_vig):.4f} qg={qg_vig}")
        print(f"    Beau/{seed}: {pt_beau[:50]}... IC={ic(pt_beau):.4f} qg={qg_beau}")

    # ── 9. Additional: Unique letter counts & distribution metrics ──────
    print("\n[9] ADDITIONAL DISTRIBUTION METRICS")
    for label, text in [("ORIGINAL CT", CT), ("ATBASH CT", atbash_ct)]:
        counts = Counter(text)
        unique = len(counts)
        most_common = counts.most_common(5)
        least_common = counts.most_common()[-5:]
        print(f"\n  {label}:")
        print(f"    Unique letters: {unique}/26")
        print(f"    Most common:  {most_common}")
        print(f"    Least common: {least_common}")
        # Frequency uniformity: stdev of counts
        mean_count = len(text) / 26
        variance = sum((c - mean_count)**2 for c in counts.values()) / 26
        stdev = variance ** 0.5
        print(f"    Mean count: {mean_count:.2f}, StDev: {stdev:.2f}")

    # ── 10. Atbash property: does it change any structural feature? ─────
    print("\n[10] STRUCTURAL COMPARISON")
    # Same letter positions (where Atbash(c) == c)
    # Atbash fixpoints: A<->Z, B<->Y, ..., M<->N. No fixpoints.
    fixpoints = [i for i in range(CT_LEN) if CT[i] == atbash_ct[i]]
    print(f"  Positions where CT[i] == Atbash(CT[i]): {fixpoints}")
    print(f"  (Atbash has no fixpoints since no letter maps to itself)")

    # Positions where CT and Atbash share the same letter at same position
    # This is impossible since Atbash maps every letter to a different one
    # But let's check letters that are "close" in the alphabet
    # More useful: where does the Atbash CT have the same letter as the
    # original CT at a DIFFERENT position?
    print("\n  Shared letter inventory:")
    orig_set = set(CT)
    atb_set = set(atbash_ct)
    print(f"    Letters in original only: {sorted(orig_set - atb_set)}")
    print(f"    Letters in Atbash only:   {sorted(atb_set - orig_set)}")
    print(f"    Letters in both:          {sorted(orig_set & atb_set)}")

    print("\n" + "=" * 72)
    print("E-ATBASH-02 SUMMARY")
    print("=" * 72)
    print("""
Key findings:
1. IC is PRESERVED under Atbash (monoalphabetic substitution) - no new
   information from IC comparison.
2. Letter frequencies are MIRROR-FLIPPED: high-frequency letters in
   original become different-frequency letters in Atbash, but the overall
   distribution shape is identical.
3. Atbash is its own inverse - fully reversible.
4. The chi-squared distances from English may differ because Atbash
   remaps which letters carry which frequencies.
5. Check trigram/bigram repeats and autokey results above for any signal.
""")


if __name__ == "__main__":
    main()
