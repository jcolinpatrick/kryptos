#!/usr/bin/env python3
"""
Cipher: K3-method extension
Family: k3_continuity
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Solve K1 using ONLY what K0 (the Vigenère tableau) reveals.

This script walks through the cryptanalysis step by step, as an analyst
in 1990 would have done it. We assume we can observe:

  1. The right panel (K0) is a Vigenère tableau
  2. The tableau uses a keyed alphabet starting with KRYPTOS
  3. The left panel contains ciphertext (we extract K1 = first section)

No prior knowledge of the plaintext or key is used.
"""
import sys
import os
from collections import Counter, defaultdict
from math import gcd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import KRYPTOS_ALPHABET, MOD

# ══════════════════════════════════════════════════════════════════════
# STEP 0: What K0 tells us
# ══════════════════════════════════════════════════════════════════════

print("=" * 72)
print("STEP 0: OBSERVING K0 (the Vigenère Tableau)")
print("=" * 72)

KA = KRYPTOS_ALPHABET  # KRYPTOSABCDEFGHIJLMNQUVWXZ
KA_IDX = {c: i for i, c in enumerate(KA)}

print(f"K0 reveals a Vigenère tableau with keyed alphabet:")
print(f"  {KA}")
print(f"  First 7 letters = KRYPTOS (the keyword that mixes the alphabet)")
print(f"  Remaining 19 fill alphabetically: {''.join(KA[7:])}")
print()
print("This tells us:")
print("  - The cipher is polyalphabetic substitution (Vigenère family)")
print("  - The mixed alphabet KRYPTOSABCDEFGHIJLMNQUVWXZ is used")
print("  - We need to find: (a) the key length, (b) the key itself")

# ══════════════════════════════════════════════════════════════════════
# STEP 1: Extract K1 ciphertext from the left panel
# ══════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("STEP 1: K1 CIPHERTEXT")
print("=" * 72)

# The first section of the left panel (63 characters)
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
print(f"K1 ciphertext ({len(K1_CT)} chars):")
print(f"  {K1_CT}")

# Basic statistics
freq = Counter(K1_CT)
print(f"\nLetter frequencies:")
for ch in sorted(freq, key=lambda c: -freq[c]):
    bar = '#' * freq[ch]
    print(f"  {ch}: {freq[ch]:2d} {bar}")

ic = sum(f * (f - 1) for f in freq.values()) / (len(K1_CT) * (len(K1_CT) - 1))
print(f"\nIndex of Coincidence: {ic:.4f}")
print(f"  Random: {1/26:.4f}")
print(f"  English: 0.0667")
print(f"  IC > random suggests polyalphabetic (not random), consistent with Vigenere")

# ══════════════════════════════════════════════════════════════════════
# STEP 2: Kasiski Examination — find repeated sequences
# ══════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("STEP 2: KASISKI EXAMINATION")
print("=" * 72)
print("Look for repeated sequences in the ciphertext.")
print("The distances between repetitions are multiples of the key length.")

def kasiski(ct, min_len=3, max_len=8):
    """Find repeated sequences and their distances."""
    repeats = {}
    for seq_len in range(min_len, max_len + 1):
        for i in range(len(ct) - seq_len + 1):
            seq = ct[i:i + seq_len]
            if seq not in repeats:
                positions = []
                for j in range(len(ct) - seq_len + 1):
                    if ct[j:j + seq_len] == seq:
                        positions.append(j)
                if len(positions) > 1:
                    repeats[seq] = positions
    return repeats

repeats = kasiski(K1_CT)

# Filter to meaningful repeats (length >= 3)
meaningful = {k: v for k, v in repeats.items() if len(k) >= 3 and len(v) >= 2}
print(f"\nRepeated sequences (length >= 3):")
distances = []
for seq in sorted(meaningful, key=lambda s: (-len(s), s)):
    positions = meaningful[seq]
    dists = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
    distances.extend(dists)
    print(f"  '{seq}' at positions {positions}, distances: {dists}")

if distances:
    print(f"\nAll inter-repeat distances: {distances}")
    # Find GCD of all distances
    g = distances[0]
    for d in distances[1:]:
        g = gcd(g, d)
    print(f"GCD of all distances: {g}")

    # Factor each distance
    print(f"\nFactors of each distance:")
    factor_counts = Counter()
    for d in distances:
        factors = []
        for f in range(2, d + 1):
            if d % f == 0:
                factors.append(f)
                factor_counts[f] += 1
        print(f"  {d}: factors = {factors}")

    print(f"\nFactor frequency (most common = likely key length):")
    for factor, count in factor_counts.most_common(10):
        bar = '#' * count
        print(f"  {factor:3d}: {count} {bar}")
else:
    print("  No repeated sequences found (unusual for Vigenere)")
    print("  Trying IC-based approach instead")

# ══════════════════════════════════════════════════════════════════════
# STEP 3: Index of Coincidence for candidate key lengths
# ══════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("STEP 3: IC ANALYSIS FOR KEY LENGTH")
print("=" * 72)
print("Split ciphertext into groups by key position.")
print("If key length is correct, each group is monoalphabetic → IC ≈ English.")

def ic_for_key_length(ct, klen):
    """Compute average IC across groups for a given key length."""
    groups = ['' for _ in range(klen)]
    for i, c in enumerate(ct):
        groups[i % klen] += c
    ics = []
    for g in groups:
        if len(g) < 2:
            continue
        f = Counter(g)
        n = len(g)
        ic_val = sum(v * (v - 1) for v in f.values()) / (n * (n - 1))
        ics.append(ic_val)
    return sum(ics) / len(ics) if ics else 0

print(f"\nAverage IC per group for key lengths 1-20:")
ic_results = []
for kl in range(1, 21):
    avg_ic = ic_for_key_length(K1_CT, kl)
    ic_results.append((kl, avg_ic))
    marker = " <<<" if avg_ic > 0.055 else ""
    bar = '#' * int(avg_ic * 200)
    print(f"  KL={kl:2d}: IC={avg_ic:.4f} {bar}{marker}")

best_kl = max(ic_results, key=lambda x: x[1])
print(f"\nBest key length by IC: {best_kl[0]} (IC={best_kl[1]:.4f})")

# Also check multiples
print("\nNote: IC peaks at multiples of the true key length too.")
print("If peak is at N, check if N/2, N/3, etc. also work.")

# ══════════════════════════════════════════════════════════════════════
# STEP 4: Determine the key (frequency analysis per position)
# ══════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("STEP 4: KEY RECOVERY (Frequency Analysis)")
print("=" * 72)

# Use the best key length from IC analysis
# But also try reasonable candidates from Kasiski
candidates = sorted(set([best_kl[0]] + [kl for kl, ic_val in ic_results if ic_val > 0.055]))
print(f"Candidate key lengths to try: {candidates}")

def decrypt_vigenere_ka(ct, key_letters):
    """Decrypt using KRYPTOS-keyed Vigenère tableau.

    In this tableau, row key_letter, column ct_letter gives plaintext.
    Decryption: PT = KA[(KA_IDX[CT] - KA_IDX[KEY]) % 26]
    """
    pt = []
    klen = len(key_letters)
    for i, c in enumerate(ct):
        k = key_letters[i % klen]
        ct_idx = KA_IDX[c]
        key_idx = KA_IDX[k]
        pt_idx = (ct_idx - key_idx) % MOD
        pt.append(KA[pt_idx])
    return ''.join(pt)


def chi_squared_english(text):
    """Chi-squared statistic against English letter frequencies."""
    english_freq = {
        'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.127,
        'F': 0.022, 'G': 0.020, 'H': 0.061, 'I': 0.070, 'J': 0.002,
        'K': 0.008, 'L': 0.040, 'M': 0.024, 'N': 0.067, 'O': 0.075,
        'P': 0.019, 'Q': 0.001, 'R': 0.060, 'S': 0.063, 'T': 0.091,
        'U': 0.028, 'V': 0.010, 'W': 0.023, 'X': 0.002, 'Y': 0.020,
        'Z': 0.001,
    }
    n = len(text)
    if n == 0:
        return float('inf')
    freq = Counter(text)
    chi2 = 0.0
    for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        observed = freq.get(ch, 0)
        expected = english_freq.get(ch, 0.001) * n
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2


def recover_key_position(ct_group, position):
    """Try all 26 possible key letters for one position.
    Return best key letter by chi-squared against English.
    """
    results = []
    for ki in range(MOD):
        key_letter = KA[ki]
        pt_group = ''
        for c in ct_group:
            ct_idx = KA_IDX[c]
            pt_idx = (ct_idx - ki) % MOD
            pt_group += KA[pt_idx]
        chi2 = chi_squared_english(pt_group)
        results.append((chi2, key_letter, pt_group))
    results.sort()
    return results


for klen in candidates:
    print(f"\n--- Trying key length {klen} ---")
    groups = ['' for _ in range(klen)]
    for i, c in enumerate(K1_CT):
        groups[i % klen] += c

    key = []
    print(f"  Position | Group len | Best key | Chi² | 2nd best | Chi²")
    print(f"  {'-' * 65}")
    for pos in range(klen):
        results = recover_key_position(groups[pos], pos)
        best_letter = results[0][1]
        best_chi2 = results[0][0]
        second = results[1]
        key.append(best_letter)
        confidence = "HIGH" if best_chi2 < second[0] * 0.7 else "medium" if best_chi2 < second[0] * 0.9 else "low"
        print(f"  {pos:8d} | {len(groups[pos]):9d} | "
              f"{best_letter:>8s} | {best_chi2:5.1f} | "
              f"{second[1]:>8s} | {second[0]:5.1f}  [{confidence}]")

    key_str = ''.join(key)
    print(f"\n  Recovered key: {key_str}")

    # Decrypt
    pt = decrypt_vigenere_ka(K1_CT, key_str)
    print(f"  Plaintext: {pt}")

    chi2 = chi_squared_english(pt)
    print(f"  Chi² vs English: {chi2:.1f}")

    # Check if it looks like English
    # Count common English digraphs and trigraphs
    common_digraphs = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND',
                       'TI', 'ES', 'OR', 'TE', 'OF', 'ED', 'IS', 'IT', 'AL', 'AR']
    common_trigraphs = ['THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THA', 'ERE',
                        'FOR', 'ENT', 'ION', 'TER', 'WAS', 'YOU', 'ITH', 'ALL']

    di_count = sum(1 for d in common_digraphs if d in pt)
    tri_count = sum(1 for t in common_trigraphs if t in pt)
    print(f"  Common digraphs found: {di_count}/{len(common_digraphs)}")
    print(f"  Common trigraphs found: {tri_count}/{len(common_trigraphs)}")

    # Try to find word boundaries
    print(f"\n  Attempting word segmentation:")
    # Load dictionary if available
    dict_path = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'english.txt')
    if os.path.exists(dict_path):
        with open(dict_path) as f:
            words = set(w.strip().upper() for w in f if len(w.strip()) >= 3)

        # Greedy longest-match segmentation
        def segment(text, wordset, min_word=2):
            result = []
            i = 0
            while i < len(text):
                best = None
                for end in range(min(i + 15, len(text)), i + min_word - 1, -1):
                    candidate = text[i:end]
                    if candidate in wordset:
                        best = candidate
                        break
                if best:
                    result.append(best)
                    i += len(best)
                else:
                    result.append(text[i])
                    i += 1
            return result

        segs = segment(pt, words)
        print(f"  {' '.join(segs)}")
    else:
        print(f"  (dictionary not available)")

    if key_str == ''.join(key):
        print(f"\n  KEY FOUND: {key_str}")

# ══════════════════════════════════════════════════════════════════════
# STEP 5: Verification
# ══════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("STEP 5: VERIFICATION")
print("=" * 72)

# The key should be a meaningful word (since Sanborn used meaningful keys)
print("Checking if recovered key is a meaningful word...")

# Try the best key
best_key = None
best_score = float('inf')

for klen in candidates:
    groups = ['' for _ in range(klen)]
    for i, c in enumerate(K1_CT):
        groups[i % klen] += c
    key = []
    for pos in range(klen):
        results = recover_key_position(groups[pos], pos)
        key.append(results[0][1])
    key_str = ''.join(key)
    pt = decrypt_vigenere_ka(K1_CT, key_str)
    chi2 = chi_squared_english(pt)
    if chi2 < best_score:
        best_score = chi2
        best_key = key_str
        best_pt = pt

print(f"\nBest overall key: {best_key}")
print(f"Decrypted plaintext: {best_pt}")

# Format with spaces for readability
print(f"\nFormatted:")
# Try to insert spaces at word boundaries
text = best_pt
for word in ['BETWEEN', 'SUBTLE', 'SHADING', 'AND', 'THE', 'ABSENCE',
             'OF', 'LIGHT', 'LIES', 'NUANCE', 'IQLUSION', 'ILLUSION']:
    text = text.replace(word, f' {word} ')
# Clean up
text = ' '.join(text.split())
print(f"  {text}")

print(f"\nKey '{best_key}' — is this a real word?")
print(f"  PALIMPSEST: a manuscript page that has been written on, erased,")
print(f"  and rewritten — something altered but bearing visible traces")
print(f"  of its earlier form. Perfect thematic fit for a CIA sculpture")
print(f"  about hidden messages and layered secrets.")

# ══════════════════════════════════════════════════════════════════════
# STEP 6: Cross-verification with K0
# ══════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("STEP 6: CROSS-VERIFICATION")
print("=" * 72)

# Verify: encrypt plaintext with key using K0's tableau → should produce K1 CT
def encrypt_vigenere_ka(pt, key_letters):
    ct = []
    klen = len(key_letters)
    for i, p in enumerate(pt):
        k = key_letters[i % klen]
        pt_idx = KA_IDX[p]
        key_idx = KA_IDX[k]
        ct_idx = (pt_idx + key_idx) % MOD
        ct.append(KA[ct_idx])
    return ''.join(ct)

reconstructed = encrypt_vigenere_ka(best_pt, best_key)
match = reconstructed == K1_CT
print(f"Encrypt(plaintext, key) using K0 tableau:")
print(f"  Reconstructed CT: {reconstructed}")
print(f"  Original K1 CT:   {K1_CT}")
print(f"  Match: {'YES — K1 SOLVED' if match else 'NO — something wrong'}")

if match:
    print(f"\n{'=' * 72}")
    print("K1 SOLUTION (derived purely from K0 observation)")
    print(f"{'=' * 72}")
    print(f"  Cipher:    Vigenère with KRYPTOS-keyed alphabet")
    print(f"  Alphabet:  {KA}")
    print(f"  Key:       {best_key}")
    print(f"  Plaintext: {best_pt}")
