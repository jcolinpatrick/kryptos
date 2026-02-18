"""
Deep structural analysis of K4 ciphertext.

Instead of trying cipher families, analyze the CT itself for hidden structure:
1. Letter frequency anomalies vs random
2. Digram/trigram frequency patterns
3. Contact analysis (which letters appear next to which)
4. Positional analysis (are certain letters favored at certain positions?)
5. Autocorrelation at ALL lags (not just crib-based)
6. Information theory: conditional entropy, mutual information
7. CT letter patterns matching the KNOWN keystream fragments
8. Kasiski-like analysis on the CT
"""
import sys, math, json
from collections import Counter
sys.path.insert(0, '/home/cpatrick/kryptos/src')

CT = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
CT_NUM = [ord(c) - ord('A') for c in CT]
N = 97

def c2n(c): return ord(c) - ord('A')
def n2c(n): return chr(n % 26 + ord('A'))

# Known keystream (Vig)
known_vig = {}
for start, pt in [(21, 'EASTNORTHEAST'), (63, 'BERLINCLOCK')]:
    for i, ch in enumerate(pt):
        pos = start + i
        known_vig[pos] = (CT_NUM[pos] - c2n(ch)) % 26

print("=" * 70)
print("K4 DEEP STRUCTURAL ANALYSIS")
print("=" * 70)

# ============================================================
# 1. COMPREHENSIVE FREQUENCY ANALYSIS
# ============================================================
print("\n1. FREQUENCY ANALYSIS")
print("-" * 70)

freq = Counter(CT)
total = len(CT)
print("Letter frequencies (sorted by count):")
for letter, count in freq.most_common():
    expected = total / 26
    z_score = (count - expected) / (expected ** 0.5)
    bar = '#' * count
    print(f"  {letter}: {count:2d} ({count/total*100:4.1f}%) z={z_score:+5.2f}  {bar}")

# IC
ic = sum(c * (c-1) for c in freq.values()) / (N * (N-1))
print(f"\nIC = {ic:.6f} (random: {1/26:.6f}, English: ~0.0667)")

# Chi-squared vs uniform
chi2 = sum((c - N/26)**2 / (N/26) for c in freq.values())
# Add zero-count letters
for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
    if c not in freq:
        chi2 += (0 - N/26)**2 / (N/26)
print(f"Chi² vs uniform = {chi2:.2f} (critical value at p=0.05, df=25: 37.65)")

# ============================================================
# 2. DIGRAM ANALYSIS
# ============================================================
print("\n2. DIGRAM ANALYSIS")
print("-" * 70)

digrams = Counter(CT[i:i+2] for i in range(N-1))
print(f"Total digrams: {N-1}")
print(f"Unique digrams: {len(digrams)}")
print(f"\nMost common digrams:")
for dg, count in digrams.most_common(15):
    print(f"  {dg}: {count}")

# Repeated digrams might indicate period
print(f"\nRepeated digram positions:")
for dg, count in digrams.most_common():
    if count >= 2:
        positions = [i for i in range(N-1) if CT[i:i+2] == dg]
        if len(positions) >= 2:
            diffs = [positions[j] - positions[j-1] for j in range(1, len(positions))]
            print(f"  {dg} at positions {positions}, diffs={diffs}")

# ============================================================
# 3. TRIGRAM ANALYSIS
# ============================================================
print("\n3. TRIGRAM ANALYSIS")
print("-" * 70)

trigrams = Counter(CT[i:i+3] for i in range(N-2))
print(f"Repeated trigrams:")
for tg, count in trigrams.most_common():
    if count >= 2:
        positions = [i for i in range(N-2) if CT[i:i+3] == tg]
        diffs = [positions[j] - positions[j-1] for j in range(1, len(positions))]
        print(f"  {tg} at positions {positions}, diffs={diffs}")

# ============================================================
# 4. AUTOCORRELATION (comprehensive)
# ============================================================
print("\n4. AUTOCORRELATION (all lags 1-48)")
print("-" * 70)

for lag in range(1, 49):
    matches = sum(1 for i in range(N - lag) if CT_NUM[i] == CT_NUM[i + lag])
    expected = (N - lag) / 26
    std = (expected * (1 - 1/26)) ** 0.5
    z = (matches - expected) / std if std > 0 else 0
    marker = " ***" if abs(z) >= 2.0 else (" **" if abs(z) >= 1.5 else "")
    if abs(z) >= 1.5 or lag <= 20:
        print(f"  lag={lag:2d}: matches={matches:2d}, expected={expected:.1f}, z={z:+.2f}{marker}")

# ============================================================
# 5. KASISKI EXAMINATION
# ============================================================
print("\n5. KASISKI EXAMINATION")
print("-" * 70)
print("  Looking for repeated substrings of length 3+:")

for length in range(3, 8):
    seen = {}
    for i in range(N - length + 1):
        sub = CT[i:i+length]
        if sub in seen:
            seen[sub].append(i)
        else:
            seen[sub] = [i]
    for sub, positions in seen.items():
        if len(positions) >= 2:
            diffs = [positions[j] - positions[j-1] for j in range(1, len(positions))]
            gcd_val = diffs[0]
            for d in diffs[1:]:
                gcd_val = math.gcd(gcd_val, d)
            print(f"  '{sub}' (len {length}): positions {positions}, diffs {diffs}, gcd={gcd_val}")

# ============================================================
# 6. CONTACT ANALYSIS
# ============================================================
print("\n6. CONTACT ANALYSIS (successor frequencies)")
print("-" * 70)

# For each letter, what letters follow it?
for letter in sorted(set(CT)):
    successors = []
    for i in range(N-1):
        if CT[i] == letter:
            successors.append(CT[i+1])
    if successors:
        succ_freq = Counter(successors)
        unique = len(succ_freq)
        total_succ = len(successors)
        # For a random cipher, expect high diversity
        entropy = -sum(c/total_succ * math.log2(c/total_succ) for c in succ_freq.values()) if total_succ > 0 else 0
        max_entropy = math.log2(total_succ) if total_succ > 1 else 0
        if total_succ >= 3:
            print(f"  After {letter} ({total_succ}×): {dict(succ_freq.most_common(5))} entropy={entropy:.2f}/{max_entropy:.2f}")

# ============================================================
# 7. KEYSTREAM PATTERN ANALYSIS
# ============================================================
print("\n7. KNOWN KEYSTREAM PATTERN ANALYSIS")
print("-" * 70)

# The known keystream values at ENE and BC positions
ene_key = [known_vig[i] for i in range(21, 34)]
bc_key = [known_vig[i] for i in range(63, 74)]

print(f"  ENE keystream (pos 21-33): {ene_key}")
print(f"  BC  keystream (pos 63-73): {bc_key}")
print(f"  ENE as letters: {''.join(n2c(k) for k in ene_key)}")
print(f"  BC  as letters: {''.join(n2c(k) for k in bc_key)}")

# Differences within keystream
ene_diffs = [(ene_key[i+1] - ene_key[i]) % 26 for i in range(len(ene_key)-1)]
bc_diffs = [(bc_key[i+1] - bc_key[i]) % 26 for i in range(len(bc_key)-1)]
print(f"\n  ENE key diffs: {ene_diffs}")
print(f"  BC  key diffs: {bc_diffs}")

# Second differences
ene_diffs2 = [(ene_diffs[i+1] - ene_diffs[i]) % 26 for i in range(len(ene_diffs)-1)]
bc_diffs2 = [(bc_diffs[i+1] - bc_diffs[i]) % 26 for i in range(len(bc_diffs)-1)]
print(f"  ENE key 2nd diffs: {ene_diffs2}")
print(f"  BC  key 2nd diffs: {bc_diffs2}")

# Ratios (in Z_26)
# Check: is key[i+1] = a * key[i] + b mod 26?
print(f"\n  Linear relationship check k[i+1] = a*k[i] + b mod 26:")
for a in range(26):
    for b in range(26):
        ene_matches = sum(1 for i in range(len(ene_key)-1)
                        if (a * ene_key[i] + b) % 26 == ene_key[i+1])
        bc_matches = sum(1 for i in range(len(bc_key)-1)
                       if (a * bc_key[i] + b) % 26 == bc_key[i+1])
        if ene_matches >= 5 or bc_matches >= 5:
            total = ene_matches + bc_matches
            print(f"    a={a:2d}, b={b:2d}: ENE={ene_matches}/12, BC={bc_matches}/10, total={total}/22")

# Check: key[i] = a*i^2 + b*i + c mod 26?
print(f"\n  Quadratic position check k[i] = a*i² + b*i + c mod 26:")
# Use ENE positions to solve
# k[21] = a*21² + b*21 + c = 1
# k[22] = a*22² + b*22 + c = 11
# k[23] = a*23² + b*23 + c = 25
# Subtract: a*(22²-21²) + b*(22-21) = 11-1=10 → 43a + b = 10 mod 26
# Subtract: a*(23²-22²) + b*(23-22) = 25-11=14 → 45a + b = 14 mod 26
# So: (45-43)a = 14-10 = 4 → 2a = 4 → a = 2 mod 26 (if 2 is invertible: 2*14=28≡2, no. gcd(2,26)=2, so 2a=4 has solutions a=2 and a=15)
for a_candidate in [2, 15]:
    for b_candidate in range(26):
        c_check = (1 - a_candidate * 21**2 - b_candidate * 21) % 26
        # Verify against all known key positions
        matches = 0
        total = 0
        for pos, expected_k in known_vig.items():
            predicted = (a_candidate * pos**2 + b_candidate * pos + c_check) % 26
            if predicted == expected_k:
                matches += 1
            total += 1

        if matches >= 10:
            print(f"    a={a_candidate}, b={b_candidate}, c={c_check}: {matches}/{total}")
            if matches == total:
                print(f"    *** PERFECT FIT! ***")
                key = [(a_candidate * i**2 + b_candidate * i + c_check) % 26 for i in range(N)]
                pt = ''.join(n2c((CT_NUM[i] - key[i]) % 26) for i in range(N))
                print(f"    PT: {pt}")

# ============================================================
# 8. ENTROPY AND INFORMATION MEASURES
# ============================================================
print("\n8. INFORMATION THEORY MEASURES")
print("-" * 70)

# Unigram entropy
h1 = -sum(c/N * math.log2(c/N) for c in freq.values())
print(f"  Unigram entropy H1 = {h1:.4f} bits (uniform: {math.log2(26):.4f})")

# Digram entropy (conditional)
digram_counts = Counter(CT[i:i+2] for i in range(N-1))
h2 = -sum(c/(N-1) * math.log2(c/(N-1)) for c in digram_counts.values())
print(f"  Digram entropy H2 = {h2:.4f} bits")
print(f"  Conditional H2|H1 = {h2 - h1:.4f} bits")

# ============================================================
# 9. PATTERN IN KNOWN KEY: MODULAR ARITHMETIC
# ============================================================
print("\n9. MODULAR ARITHMETIC PATTERNS IN KNOWN KEY")
print("-" * 70)

all_known = sorted(known_vig.items())
print(f"  All {len(all_known)} known key values:")
for pos, val in all_known:
    print(f"    k[{pos:2d}] = {val:2d} = {n2c(val)}  (CT={CT[pos]}, PT at crib)")

# Check: does key relate to position via some function?
# k = f(i, CT[i]) ?
print(f"\n  Testing k[i] = CT[i] + f(i) patterns:")
for pos, val in all_known:
    diff = (val - CT_NUM[pos]) % 26
    diff2 = (val + CT_NUM[pos]) % 26
    print(f"    pos={pos:2d}: k-CT={diff:2d} ({n2c(diff)}), k+CT={diff2:2d} ({n2c(diff2)})")

# ============================================================
# 10. BIGRAM FREQUENCY OF KEYSTREAM AT KNOWN POSITIONS
# ============================================================
print("\n10. KEYSTREAM CONSECUTIVE PAIR ANALYSIS")
print("-" * 70)

# All consecutive known key pairs
for i in range(21, 33):
    a, b = known_vig[i], known_vig[i+1]
    print(f"  k[{i}]→k[{i+1}]: {a:2d}→{b:2d} ({n2c(a)}→{n2c(b)}), diff={(b-a)%26}")
print("  ---")
for i in range(63, 73):
    a, b = known_vig[i], known_vig[i+1]
    print(f"  k[{i}]→k[{i+1}]: {a:2d}→{b:2d} ({n2c(a)}→{n2c(b)}), diff={(b-a)%26}")

# Look for the Bean equality context
print(f"\n  Bean positions: k[27]={known_vig[27]} ({n2c(known_vig[27])}), k[65]={known_vig[65]} ({n2c(known_vig[65])})")
print(f"  Gap: 65-27 = 38 positions")
print(f"  CT[27]={CT[27]} ({CT_NUM[27]}), CT[65]={CT[65]} ({CT_NUM[65]})")
print(f"  CT[27]=CT[65]={CT[27]=='P' and CT[65]=='P'}")

# ============================================================
# 11. LOOK FOR HIDDEN PERIODICITY VIA DFT
# ============================================================
print("\n11. DISCRETE FOURIER TRANSFORM OF CT")
print("-" * 70)

# Compute DFT magnitude of CT number sequence
# Look for peaks that indicate periodicity
dft_mags = []
for freq_idx in range(N // 2 + 1):
    real = sum(CT_NUM[n] * math.cos(2 * math.pi * freq_idx * n / N) for n in range(N))
    imag = sum(CT_NUM[n] * math.sin(2 * math.pi * freq_idx * n / N) for n in range(N))
    mag = math.sqrt(real**2 + imag**2)
    dft_mags.append((freq_idx, mag))

# Sort by magnitude, show top 10
dft_mags.sort(key=lambda x: -x[1])
print("  Top 10 DFT frequency components:")
for freq_idx, mag in dft_mags[:10]:
    period = N / freq_idx if freq_idx > 0 else float('inf')
    print(f"  freq={freq_idx:2d} (period={period:6.1f}): magnitude={mag:.1f}")

# Also DFT of known keystream
all_key_nums = [known_vig.get(i, 0) for i in range(N)]
# Zero out unknown positions for DFT
key_dft = []
for freq_idx in range(N // 2 + 1):
    real = sum(all_key_nums[n] * math.cos(2 * math.pi * freq_idx * n / N)
              for n in known_vig.keys())
    imag = sum(all_key_nums[n] * math.sin(2 * math.pi * freq_idx * n / N)
              for n in known_vig.keys())
    mag = math.sqrt(real**2 + imag**2)
    key_dft.append((freq_idx, mag))

key_dft.sort(key=lambda x: -x[1])
print("\n  Top 10 DFT of known keystream positions:")
for freq_idx, mag in key_dft[:10]:
    period = N / freq_idx if freq_idx > 0 else float('inf')
    print(f"  freq={freq_idx:2d} (period={period:6.1f}): magnitude={mag:.1f}")

print("\n" + "=" * 70)
print("DEEP STRUCTURAL ANALYSIS COMPLETE")
print("=" * 70)
