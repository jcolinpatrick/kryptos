#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: yar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Statistical analysis of the YAR grille ciphertext extracted from Kryptos.

The CT was extracted by overlaying Kryptos ciphertext (K1-K4) as a grid on the
Kryptos Vigenere tableau, using Y/A/R positions as Cardan grille holes, then
reading the tableau characters through those holes.
"""

import math
from collections import Counter
from itertools import combinations

# The 106-character YAR grille ciphertext
CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

# English letter frequencies (standard)
ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}

def letter_frequency(text):
    """Compute letter frequency distribution."""
    n = len(text)
    counts = Counter(text)
    freqs = {ch: counts.get(ch, 0) / n for ch in sorted("ABCDEFGHIJKLMNOPQRSTUVWXYZ")}
    return counts, freqs

def index_of_coincidence(text):
    """Compute IC = sum(n_i * (n_i - 1)) / (N * (N - 1))."""
    n = len(text)
    counts = Counter(text)
    numerator = sum(c * (c - 1) for c in counts.values())
    return numerator / (n * (n - 1))

def bigram_freq(text, top_n=20):
    """Top bigram frequencies."""
    bigrams = [text[i:i+2] for i in range(len(text) - 1)]
    return Counter(bigrams).most_common(top_n)

def trigram_freq(text, top_n=20):
    """Top trigram frequencies."""
    trigrams = [text[i:i+3] for i in range(len(text) - 2)]
    return Counter(trigrams).most_common(top_n)

def kasiski_examination(text, min_len=3, max_len=8):
    """Find repeated sequences, compute distances, find GCD of distances."""
    repeats = {}
    for length in range(min_len, max_len + 1):
        for i in range(len(text) - length + 1):
            seq = text[i:i+length]
            if seq not in repeats:
                positions = []
                for j in range(len(text) - length + 1):
                    if text[j:j+length] == seq:
                        positions.append(j)
                if len(positions) > 1:
                    repeats[seq] = positions

    # Compute distances and GCDs
    results = []
    for seq, positions in sorted(repeats.items(), key=lambda x: (-len(x[0]), x[0])):
        distances = []
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                distances.append(positions[j] - positions[i])
        if distances:
            g = distances[0]
            for d in distances[1:]:
                g = math.gcd(g, d)
            results.append((seq, positions, distances, g))

    return results

def ic_at_period(text, period):
    """Compute average IC across substreams at given period."""
    substreams = ['' for _ in range(period)]
    for i, ch in enumerate(text):
        substreams[i % period] += ch

    ics = []
    for s in substreams:
        if len(s) > 1:
            ics.append(index_of_coincidence(s))

    return sum(ics) / len(ics) if ics else 0

def entropy(text):
    """Shannon entropy in bits."""
    n = len(text)
    counts = Counter(text)
    h = 0
    for c in counts.values():
        p = c / n
        if p > 0:
            h -= p * math.log2(p)
    return h

def chi_squared_english(text):
    """Chi-squared statistic against English letter frequencies."""
    n = len(text)
    counts = Counter(text)
    chi2 = 0
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        observed = counts.get(ch, 0)
        expected = ENGLISH_FREQ[ch] * n
        chi2 += (observed - expected) ** 2 / expected
    return chi2

def find_palindromes(text, min_len=4):
    """Find palindromic substrings."""
    results = []
    for length in range(min_len, len(text) + 1):
        for i in range(len(text) - length + 1):
            sub = text[i:i+length]
            if sub == sub[::-1]:
                results.append((i, sub))
    return results

def find_repeated_blocks(text, block_size=4):
    """Find repeated blocks of given size."""
    blocks = {}
    for i in range(len(text) - block_size + 1):
        block = text[i:i+block_size]
        if block not in blocks:
            blocks[block] = []
        blocks[block].append(i)
    return {k: v for k, v in blocks.items() if len(v) > 1}

# ============================================================
# RUN ANALYSIS
# ============================================================

print("=" * 70)
print("STATISTICAL ANALYSIS OF YAR GRILLE CIPHERTEXT")
print("=" * 70)
print(f"\nCT: {CT}")
print(f"Length: {len(CT)}")
print(f"Unique letters: {len(set(CT))} / 26")
print(f"Letters present: {''.join(sorted(set(CT)))}")
missing = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") - set(CT)
print(f"Letters missing: {''.join(sorted(missing)) if missing else 'NONE'}")

# 1. Letter frequency
print("\n" + "=" * 70)
print("1. LETTER FREQUENCY DISTRIBUTION")
print("=" * 70)
counts, freqs = letter_frequency(CT)
print(f"\n{'Letter':>6} {'Count':>6} {'Freq':>8} {'English':>8} {'Delta':>8} {'Bar'}")
print("-" * 60)
for ch, count in sorted(counts.items(), key=lambda x: -x[1]):
    f = freqs[ch]
    eng = ENGLISH_FREQ[ch]
    delta = f - eng
    bar = '#' * int(count)
    print(f"{ch:>6} {count:>6} {f:>8.4f} {eng:>8.4f} {delta:>+8.4f} {bar}")

# Letters not in CT
for ch in sorted(missing):
    eng = ENGLISH_FREQ[ch]
    print(f"{ch:>6} {0:>6} {0:>8.4f} {eng:>8.4f} {-eng:>+8.4f}")

# 2. Index of Coincidence
print("\n" + "=" * 70)
print("2. INDEX OF COINCIDENCE")
print("=" * 70)
ic = index_of_coincidence(CT)
print(f"\nIC = {ic:.6f}")
print(f"English IC    = 0.066700")
print(f"Random IC     = 0.038462")
print(f"K4 IC         = 0.036100")
if ic > 0.060:
    print("Assessment: NEAR ENGLISH — suggests monoalphabetic or low-period polyalphabetic")
elif ic > 0.050:
    print("Assessment: ELEVATED — suggests low-period polyalphabetic (period 2-4)")
elif ic > 0.042:
    print("Assessment: SLIGHTLY ELEVATED — suggests polyalphabetic (period 4-8)")
elif ic > 0.036:
    print("Assessment: NEAR RANDOM — suggests high-period polyalphabetic or well-mixed")
else:
    print("Assessment: BELOW RANDOM — unusual, suggests very high mixing or non-standard process")

# 3. Bigram and trigram frequency
print("\n" + "=" * 70)
print("3. BIGRAM FREQUENCY (top 20)")
print("=" * 70)
for bg, count in bigram_freq(CT, 20):
    print(f"  {bg}: {count}")

print("\n" + "=" * 70)
print("3b. TRIGRAM FREQUENCY (top 20)")
print("=" * 70)
for tg, count in trigram_freq(CT, 20):
    print(f"  {tg}: {count}")

# 4. Kasiski examination
print("\n" + "=" * 70)
print("4. KASISKI EXAMINATION")
print("=" * 70)
kasiski_results = kasiski_examination(CT)
# Filter to length >= 3 repeats
long_repeats = [r for r in kasiski_results if len(r[0]) >= 3]
if long_repeats:
    print(f"\nFound {len(long_repeats)} repeated sequences (length >= 3):")
    # Show longest first, then alphabetical
    for seq, positions, distances, g in sorted(long_repeats, key=lambda x: (-len(x[0]), x[0])):
        print(f"  '{seq}' at positions {positions}, distances={distances}, GCD={g}")

    # Aggregate distance GCDs
    all_distances = []
    for _, _, distances, _ in long_repeats:
        all_distances.extend(distances)

    # Factor frequency analysis
    print("\n  Factor frequency analysis (from all Kasiski distances):")
    factor_counts = Counter()
    for d in all_distances:
        for f in range(2, d + 1):
            if d % f == 0:
                factor_counts[f] += 1
    for factor, count in factor_counts.most_common(15):
        print(f"    Factor {factor:>3}: appears {count} times")
else:
    print("\nNo repeated sequences of length >= 3 found.")

# Also show bigram repeats for completeness
bigram_repeats = [r for r in kasiski_results if len(r[0]) == 2 and len(r[1]) >= 3]
if bigram_repeats:
    print(f"\n  Notable bigram repeats (3+ occurrences):")
    for seq, positions, distances, g in sorted(bigram_repeats, key=lambda x: -len(x[1]))[:10]:
        print(f"    '{seq}' at {positions}, GCD={g}")

# 5. IC at various periods
print("\n" + "=" * 70)
print("5. IC AT VARIOUS ASSUMED PERIODS")
print("=" * 70)
print(f"\n{'Period':>7} {'Avg IC':>10} {'Assessment'}")
print("-" * 50)
best_period = 0
best_ic = 0
for p in range(1, 16):
    pic = ic_at_period(CT, p)
    if pic > best_ic:
        best_ic = pic
        best_period = p
    marker = ""
    if pic > 0.060:
        marker = "<-- ENGLISH-LIKE"
    elif pic > 0.050:
        marker = "<-- elevated"
    elif pic > 0.045:
        marker = "<-- slightly elevated"
    print(f"{p:>7} {pic:>10.6f} {marker}")

print(f"\nBest period: {best_period} (IC = {best_ic:.6f})")

# Also check periods 16-30 for completeness
print("\nExtended period check (16-30):")
for p in range(16, 31):
    pic = ic_at_period(CT, p)
    if pic > best_ic:
        best_ic = pic
        best_period = p
    marker = ""
    if pic > 0.060:
        marker = "<-- ENGLISH-LIKE"
    elif pic > 0.050:
        marker = "<-- elevated"
    print(f"{p:>7} {pic:>10.6f} {marker}")

print(f"\nOverall best period: {best_period} (IC = {best_ic:.6f})")

# 6. Entropy
print("\n" + "=" * 70)
print("6. ENTROPY")
print("=" * 70)
h = entropy(CT)
print(f"\nShannon entropy: {h:.4f} bits/letter")
print(f"English text:    ~4.19 bits/letter")
print(f"Random 26-letter: {math.log2(26):.4f} bits/letter")
if h > 4.5:
    print("Assessment: HIGH entropy — near-random distribution")
elif h > 4.3:
    print("Assessment: MODERATELY HIGH — some structure but well-distributed")
elif h > 4.0:
    print("Assessment: MODERATE — noticeable frequency bias")
else:
    print("Assessment: LOW — significant frequency bias (monoalphabetic-like)")

# 7. Chi-squared
print("\n" + "=" * 70)
print("7. CHI-SQUARED TEST vs ENGLISH")
print("=" * 70)
chi2 = chi_squared_english(CT)
print(f"\nChi-squared statistic: {chi2:.2f}")
print(f"Degrees of freedom: 25")
print(f"For df=25: critical values at p=0.05: 37.65, p=0.01: 44.31")
if chi2 < 37.65:
    print("Assessment: CONSISTENT with English (fail to reject null at p=0.05)")
elif chi2 < 44.31:
    print("Assessment: MARGINALLY inconsistent with English (reject at p=0.05 but not p=0.01)")
else:
    print("Assessment: STRONGLY inconsistent with English (reject at p=0.01)")

# 8. Notable patterns
print("\n" + "=" * 70)
print("8. NOTABLE PATTERNS")
print("=" * 70)

# Palindromes
print("\n8a. Palindromic substrings (length >= 4):")
palindromes = find_palindromes(CT, 4)
if palindromes:
    for pos, pal in palindromes:
        print(f"  Position {pos}: '{pal}'")
else:
    print("  None found.")

# Repeated blocks
print("\n8b. Repeated 4-char blocks:")
rep_blocks = find_repeated_blocks(CT, 4)
if rep_blocks:
    for block, positions in sorted(rep_blocks.items()):
        print(f"  '{block}' at positions {positions}")
else:
    print("  None found.")

print("\n8c. Repeated 3-char blocks:")
rep_blocks3 = find_repeated_blocks(CT, 3)
if rep_blocks3:
    for block, positions in sorted(rep_blocks3.items()):
        print(f"  '{block}' at positions {positions}")
else:
    print("  None found.")

# Letter spacing patterns
print("\n8d. Letter doubling (consecutive same letter):")
for i in range(len(CT) - 1):
    if CT[i] == CT[i+1]:
        print(f"  Position {i}-{i+1}: '{CT[i]}{CT[i+1]}'")

# Runs of ascending/descending letters
print("\n8e. Alphabetic runs (3+ consecutive letters in alpha order):")
for i in range(len(CT) - 2):
    run = [CT[i]]
    j = i + 1
    while j < len(CT) and ord(CT[j]) == ord(CT[j-1]) + 1:
        run.append(CT[j])
        j += 1
    if len(run) >= 3:
        print(f"  Position {i}: '{''.join(run)}' (ascending)")
    run = [CT[i]]
    j = i + 1
    while j < len(CT) and ord(CT[j]) == ord(CT[j-1]) - 1:
        run.append(CT[j])
        j += 1
    if len(run) >= 3:
        print(f"  Position {i}: '{''.join(run)}' (descending)")

# Check for interesting substrings (words)
print("\n8f. English-like substrings visible in CT:")
common_words = ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HER',
                'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'HAD', 'HAS', 'HIS', 'HOW', 'MAN',
                'NEW', 'NOW', 'OLD', 'SEE', 'WAY', 'WHO', 'DID', 'GET', 'HIM', 'LET',
                'SAY', 'SHE', 'TOO', 'USE', 'KEY', 'CIA', 'NSA', 'LUX', 'PAD', 'ACE',
                'ILL', 'DIN', 'GIL', 'VIA', 'WAF', 'FIG', 'KIN', 'MUK', 'RIL', 'JUF',
                'EAST', 'NORTH', 'CLOCK', 'BERLIN', 'LIGHT', 'KRYPTOS', 'SHADOW',
                'KILL', 'KNIFE', 'FACE', 'MINE', 'WIND', 'FILM', 'SILK',
                'PACE', 'DIME', 'VEIL', 'WILY', 'ACID', 'NICK', 'LUCK']
for word in common_words:
    pos = CT.find(word)
    while pos != -1:
        print(f"  '{word}' at position {pos}")
        pos = CT.find(word, pos + 1)

# Position analysis - look for the known K4 cribs
print("\n8g. Check for K4 known plaintext fragments:")
from kryptos.kernel.constants import CT as K4_CIPHERTEXT
print(f"  K4 CT: {K4_CIPHERTEXT}")
# Check if any fragment of YAR CT matches K4 CT fragments
for length in range(5, 15):
    for i in range(len(CT) - length + 1):
        fragment = CT[i:i+length]
        pos = K4_CIPHERTEXT.find(fragment)
        if pos != -1:
            print(f"  YAR[{i}:{i+length}] = '{fragment}' matches K4[{pos}:{pos+length}]")

# Distribution evenness metric
print("\n8h. Distribution evenness:")
expected_uniform = len(CT) / 26
counts_list = [counts.get(ch, 0) for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
variance = sum((c - expected_uniform) ** 2 for c in counts_list) / 26
std_dev = math.sqrt(variance)
print(f"  Expected uniform count: {expected_uniform:.2f}")
print(f"  Actual std deviation: {std_dev:.2f}")
print(f"  Max count: {max(counts_list)} ({[ch for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if counts.get(ch,0) == max(counts_list)]})")
print(f"  Min count (nonzero): {min(c for c in counts_list if c > 0)} ({[ch for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if counts.get(ch,0) == min(c for c in counts_list if c > 0)]})")

# Vowel/consonant ratio
print("\n8i. Vowel/consonant analysis:")
vowels = sum(1 for ch in CT if ch in 'AEIOU')
consonants = len(CT) - vowels
print(f"  Vowels: {vowels} ({vowels/len(CT)*100:.1f}%)")
print(f"  Consonants: {consonants} ({consonants/len(CT)*100:.1f}%)")
print(f"  English expected: ~38-40% vowels")

# Positional analysis - first half vs second half
print("\n8j. First half vs second half IC:")
half = len(CT) // 2
ic1 = index_of_coincidence(CT[:half])
ic2 = index_of_coincidence(CT[half:])
print(f"  First half  (positions 0-{half-1}):  IC = {ic1:.6f}")
print(f"  Second half (positions {half}-{len(CT)-1}): IC = {ic2:.6f}")

# Autocorrelation
print("\n8k. Autocorrelation (coincidences at each shift):")
for shift in range(1, min(30, len(CT))):
    matches = sum(1 for i in range(len(CT) - shift) if CT[i] == CT[i + shift])
    expected = (len(CT) - shift) / 26
    ratio = matches / expected if expected > 0 else 0
    bar = '*' * matches
    marker = " <--" if ratio > 1.5 else ""
    print(f"  Shift {shift:>2}: {matches:>2} matches (expected {expected:.1f}, ratio {ratio:.2f}){marker} {bar}")

print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)
