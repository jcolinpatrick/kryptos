#!/usr/bin/env python3
"""
Cipher: YAR grille
Family: yar
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Treat YAR-modified K4 as the REAL ciphertext and perform full cryptanalysis.

CT: OBKKUOXOGHULBSOLIFBBWFLJVQQPUNGKSSOTWTQSJQSSEKZZWFTJKLUDIQWINFBNRPVTTMZFPKWGDKZXTJCDIGKUHUXUEKCCD
IC at period 7 = 0.0547 (vs 0.0419 for carved text) — significant signal.
"""

import sys, json, os, math
from collections import Counter
from itertools import product

sys.path.insert(0, 'src')

CT = "OBKKUOXOGHULBSOLIFBBWFLJVQQPUNGKSSOTWTQSJQSSEKZZWFTJKLUDIQWINFBNRPVTTMZFPKWGDKZXTJCDIGKUHUXUEKCCD"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# English letter frequencies
ENG_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074,
}
ENG_FREQ_VEC = [ENG_FREQ[AZ[i]] / 100.0 for i in range(26)]

# Load quadgrams
QG = {}
with open('data/english_quadgrams.json') as f:
    QG = json.load(f)

def qg_score(text):
    if len(text) < 4:
        return -10.0
    total = sum(QG.get(text[i:i+4], -10.0) for i in range(len(text) - 3))
    return total / (len(text) - 3)

def ic(text):
    freq = Counter(text)
    n = len(text)
    if n < 2:
        return 0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

def chi_squared(text, alphabet=AZ):
    """Chi-squared statistic vs English frequency."""
    freq = Counter(text)
    n = len(text)
    return sum((freq.get(c, 0) - n * ENG_FREQ[c] / 100) ** 2 / (n * ENG_FREQ[c] / 100) for c in alphabet)

def vig_decrypt(ct, key, alphabet=AZ):
    return ''.join(alphabet[(alphabet.index(c) - alphabet.index(key[i % len(key)])) % len(alphabet)]
                   for i, c in enumerate(ct))

def beau_decrypt(ct, key, alphabet=AZ):
    return ''.join(alphabet[(alphabet.index(key[i % len(key)]) - alphabet.index(c)) % len(alphabet)]
                   for i, c in enumerate(ct))

def varbeau_decrypt(ct, key, alphabet=AZ):
    return ''.join(alphabet[(alphabet.index(c) + alphabet.index(key[i % len(key)])) % len(alphabet)]
                   for i, c in enumerate(ct))

print("=" * 80)
print("COMPREHENSIVE CRYPTANALYSIS OF YAR-MODIFIED K4 CANDIDATE CT")
print("=" * 80)
print(f"\nCT: {CT}")
print(f"Length: {len(CT)}")

# ═══════════════════════════════════════════════════════════════════════════
# 1. IC ACROSS ALL PERIODS
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("1. INDEX OF COINCIDENCE BY PERIOD")
print(f"{'='*80}")

for period in range(1, 26):
    columns = ['' for _ in range(period)]
    for i, c in enumerate(CT):
        columns[i % period] += c
    avg_ic_val = sum(ic(col) for col in columns) / period
    bar = '#' * int(max(0, (avg_ic_val - 0.03)) * 2000)
    marker = " <<<" if avg_ic_val > 0.050 else ""
    print(f"  Period {period:2d}: IC={avg_ic_val:.4f} ({len(columns[0]):2d} chars/col) {bar}{marker}")

# ═══════════════════════════════════════════════════════════════════════════
# 2. PERIOD-7 COLUMN ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("2. PERIOD-7 COLUMN-BY-COLUMN ANALYSIS")
print(f"{'='*80}")

PERIOD = 7
columns = ['' for _ in range(PERIOD)]
for i, c in enumerate(CT):
    columns[i % PERIOD] += c

for col_idx, col in enumerate(columns):
    print(f"\n  Column {col_idx} ({len(col)} chars): {col}")
    freq = Counter(col)
    ic_val = ic(col)
    print(f"    IC: {ic_val:.4f}")
    print(f"    Freq: {dict(sorted(freq.items(), key=lambda x: -x[1]))}")

    # Try each shift (AZ) and compute chi-squared
    best_shifts_az = []
    for shift in range(26):
        decrypted = ''.join(AZ[(AZ.index(c) - shift) % 26] for c in col)
        chi2 = chi_squared(decrypted)
        # Correlation with English
        dec_freq = Counter(decrypted)
        corr = sum(dec_freq.get(AZ[i], 0) / len(col) * ENG_FREQ_VEC[i] for i in range(26))
        best_shifts_az.append((chi2, corr, shift, AZ[shift], decrypted))

    best_shifts_az.sort(key=lambda x: x[0])  # lowest chi2 = best
    print(f"    Best AZ shifts (by chi²):")
    for chi2, corr, shift, key_ch, dec in best_shifts_az[:5]:
        print(f"      Key={key_ch} (shift {shift:2d}): χ²={chi2:6.1f}  corr={corr:.4f}  → {dec}")

    # Same for KA
    best_shifts_ka = []
    for shift in range(26):
        decrypted = ''.join(KA[(KA.index(c) - shift) % 26] for c in col)
        chi2 = chi_squared(decrypted)
        dec_freq = Counter(decrypted)
        corr = sum(dec_freq.get(AZ[i], 0) / len(col) * ENG_FREQ_VEC[i] for i in range(26))
        best_shifts_ka.append((chi2, corr, shift, KA[shift], decrypted))

    best_shifts_ka.sort(key=lambda x: x[0])
    print(f"    Best KA shifts (by chi²):")
    for chi2, corr, shift, key_ch, dec in best_shifts_ka[:3]:
        print(f"      Key={key_ch} (shift {shift:2d}): χ²={chi2:6.1f}  corr={corr:.4f}  → {dec}")

# ═══════════════════════════════════════════════════════════════════════════
# 3. BEST KEY RECOVERY (period 7, AZ)
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("3. KEY RECOVERY — Period 7, AZ alphabet")
print(f"{'='*80}")

# For each column, find the best 3 key letters by chi-squared
best_per_col_az = []
for col_idx in range(PERIOD):
    col = columns[col_idx]
    shifts = []
    for shift in range(26):
        dec = ''.join(AZ[(AZ.index(c) - shift) % 26] for c in col)
        chi2 = chi_squared(dec)
        shifts.append((chi2, shift))
    shifts.sort()
    best_per_col_az.append(shifts[:4])  # top 4 candidates per column

print(f"\nBest key letters per column (AZ, by chi²):")
for col_idx, shifts in enumerate(best_per_col_az):
    candidates = [f"{AZ[s]}(χ²={c:.0f})" for c, s in shifts]
    print(f"  Col {col_idx}: {', '.join(candidates)}")

# Try all combinations of top 3 per column
print(f"\nTop key combinations (3^7 = {3**7} trials):")
best_keys_az = []
for combo in product(*[[(s, c) for c, s in col_shifts[:3]] for col_shifts in best_per_col_az]):
    key = ''.join(AZ[s] for s, c in combo)
    total_chi2 = sum(c for s, c in combo)
    pt = vig_decrypt(CT, key)
    score = qg_score(pt)
    best_keys_az.append((score, total_chi2, key, pt))

best_keys_az.sort(key=lambda x: -x[0])
print(f"\n  Top 15 by quadgram score:")
for score, chi2, key, pt in best_keys_az[:15]:
    print(f"    Key={key}  qg={score:+.3f}  χ²={chi2:.0f}  PT={pt}")

# ═══════════════════════════════════════════════════════════════════════════
# 4. SAME WITH KA ALPHABET
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("4. KEY RECOVERY — Period 7, KA alphabet")
print(f"{'='*80}")

best_per_col_ka = []
for col_idx in range(PERIOD):
    col = columns[col_idx]
    shifts = []
    for shift in range(26):
        dec = ''.join(KA[(KA.index(c) - shift) % 26] for c in col)
        chi2 = chi_squared(dec)
        shifts.append((chi2, shift))
    shifts.sort()
    best_per_col_ka.append(shifts[:4])

print(f"\nBest key letters per column (KA, by chi²):")
for col_idx, shifts in enumerate(best_per_col_ka):
    candidates = [f"{KA[s]}(χ²={c:.0f})" for c, s in shifts]
    print(f"  Col {col_idx}: {', '.join(candidates)}")

print(f"\nTop key combinations (3^7 = {3**7}):")
best_keys_ka = []
for combo in product(*[[(s, c) for c, s in col_shifts[:3]] for col_shifts in best_per_col_ka]):
    key = ''.join(KA[s] for s, c in combo)
    total_chi2 = sum(c for s, c in combo)
    pt = ''.join(KA[(KA.index(c) - KA.index(key[i % len(key)])) % 26] for i, c in enumerate(CT))
    score = qg_score(pt)
    best_keys_ka.append((score, total_chi2, key, pt))

best_keys_ka.sort(key=lambda x: -x[0])
print(f"\n  Top 15 by quadgram score:")
for score, chi2, key, pt in best_keys_ka[:15]:
    print(f"    Key={key}  qg={score:+.3f}  χ²={chi2:.0f}  PT={pt}")

# ═══════════════════════════════════════════════════════════════════════════
# 5. BEAUFORT ANALYSIS (period 7)
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("5. BEAUFORT KEY RECOVERY — Period 7")
print(f"{'='*80}")

best_per_col_beau = []
for col_idx in range(PERIOD):
    col = columns[col_idx]
    shifts = []
    for shift in range(26):
        # Beaufort: PT = (KEY - CT) mod 26
        dec = ''.join(AZ[(shift - AZ.index(c)) % 26] for c in col)
        chi2 = chi_squared(dec)
        shifts.append((chi2, shift))
    shifts.sort()
    best_per_col_beau.append(shifts[:4])

print(f"\nBest Beaufort key letters per column (AZ):")
for col_idx, shifts in enumerate(best_per_col_beau):
    candidates = [f"{AZ[s]}(χ²={c:.0f})" for c, s in shifts]
    print(f"  Col {col_idx}: {', '.join(candidates)}")

best_keys_beau = []
for combo in product(*[[(s, c) for c, s in col_shifts[:3]] for col_shifts in best_per_col_beau]):
    key = ''.join(AZ[s] for s, c in combo)
    total_chi2 = sum(c for s, c in combo)
    pt = beau_decrypt(CT, key)
    score = qg_score(pt)
    best_keys_beau.append((score, total_chi2, key, pt))

best_keys_beau.sort(key=lambda x: -x[0])
print(f"\n  Top 15 by quadgram score:")
for score, chi2, key, pt in best_keys_beau[:15]:
    print(f"    Key={key}  qg={score:+.3f}  χ²={chi2:.0f}  PT={pt}")

# ═══════════════════════════════════════════════════════════════════════════
# 6. KRYPTOS KEY SPECIFICALLY
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("6. KRYPTOS KEY — Detailed analysis")
print(f"{'='*80}")

for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
    for cipher_name, cipher_fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt), ("VBEAU", varbeau_decrypt)]:
        pt = cipher_fn(CT, "KRYPTOS", alph)
        score = qg_score(pt)
        pt_ic = ic(pt)
        pt_chi2 = chi_squared(pt)
        print(f"  {cipher_name}/KRYPTOS/{alph_name}: qg={score:+.3f} IC={pt_ic:.4f} χ²={pt_chi2:.0f}")
        print(f"    PT: {pt}")
        # Check for ANY English words >= 4 chars
        words_found = []
        for wlen in range(7, 3, -1):
            for pos in range(len(pt) - wlen + 1):
                substr = pt[pos:pos+wlen]
                if substr in QG or any(substr in w for w in ["THE", "AND", "FOR", "THAT", "WITH", "THIS", "FROM",
                    "HAVE", "BEEN", "WERE", "THEY", "THEIR", "WHAT", "WHEN", "YOUR",
                    "EAST", "NORTH", "BERLIN", "CLOCK", "SHADOW", "LIGHT", "TOMB",
                    "UNDER", "GROUND", "SLOWLY", "WONDERFUL", "THINGS", "BURIED",
                    "BETWEEN", "SUBTLE", "SHADING", "ABSENCE", "INVISIBLE", "IQLUSION"]):
                    pass  # too many false positives
        print()

# ═══════════════════════════════════════════════════════════════════════════
# 7. EXHAUSTIVE SHORT KEYWORD SEARCH (4-7 chars)
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("7. WORDLIST KEY SEARCH (period 7)")
print(f"{'='*80}")

# Load wordlist
wordlist_path = 'wordlists/english.txt'
if os.path.exists(wordlist_path):
    with open(wordlist_path) as f:
        words = [w.strip().upper() for w in f if 5 <= len(w.strip()) <= 10]

    # Filter to length 7 words
    words_7 = [w for w in words if len(w) == 7]
    print(f"  Testing {len(words_7)} 7-letter words...")

    best_word_results = []
    for word in words_7:
        if not all(c in AZ for c in word):
            continue
        for alph_name, alph, dfn in [("AZ", AZ, vig_decrypt), ("AZ_B", AZ, beau_decrypt)]:
            pt = dfn(CT, word, AZ if "AZ" in alph_name else KA)
            score = qg_score(pt)
            if score > -7.5:
                best_word_results.append((score, word, alph_name, pt))

    best_word_results.sort(key=lambda x: -x[0])
    print(f"\n  Top 20 7-letter words (qg > -7.5):")
    for score, word, alph_name, pt in best_word_results[:20]:
        print(f"    {word} ({alph_name}): qg={score:+.3f}  PT={pt}")

    if not best_word_results:
        print(f"  No 7-letter words produced qg > -7.5")
        # Show top 10 regardless
        all_word_results = []
        for word in words_7[:5000]:  # first 5000
            if not all(c in AZ for c in word):
                continue
            pt = vig_decrypt(CT, word)
            score = qg_score(pt)
            all_word_results.append((score, word, pt))
        all_word_results.sort(key=lambda x: -x[0])
        print(f"\n  Top 10 overall:")
        for score, word, pt in all_word_results[:10]:
            print(f"    {word}: qg={score:+.3f}  PT={pt}")

# ═══════════════════════════════════════════════════════════════════════════
# 8. KASISKI EXAMINATION
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("8. KASISKI EXAMINATION — Repeated bigrams/trigrams")
print(f"{'='*80}")

for ngram_len in [2, 3, 4]:
    repeats = {}
    for i in range(len(CT) - ngram_len + 1):
        gram = CT[i:i+ngram_len]
        if gram not in repeats:
            repeats[gram] = []
        repeats[gram].append(i)

    multi = {g: positions for g, positions in repeats.items() if len(positions) > 1}
    if multi:
        print(f"\n  Repeated {ngram_len}-grams:")
        for gram, positions in sorted(multi.items(), key=lambda x: -len(x[1])):
            spacings = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
            from math import gcd
            from functools import reduce
            g = reduce(gcd, spacings)
            factors = []
            for f in range(2, max(spacings) + 1):
                if all(s % f == 0 for s in spacings):
                    factors.append(f)
            print(f"    '{gram}' at positions {positions}, spacings {spacings}, GCD={g}, common factors: {factors[:8]}")

# ═══════════════════════════════════════════════════════════════════════════
# 9. PERIOD 14 (2×7) ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("9. PERIOD 14 (2×7) ANALYSIS")
print(f"{'='*80}")

PERIOD14 = 14
columns14 = ['' for _ in range(PERIOD14)]
for i, c in enumerate(CT):
    columns14[i % PERIOD14] += c

best_per_col_14 = []
for col_idx in range(PERIOD14):
    col = columns14[col_idx]
    shifts = []
    for shift in range(26):
        dec = ''.join(AZ[(AZ.index(c) - shift) % 26] for c in col)
        chi2 = chi_squared(dec)
        shifts.append((chi2, shift))
    shifts.sort()
    best_per_col_14.append(shifts[0])

key14 = ''.join(AZ[s] for c, s in best_per_col_14)
print(f"  Best period-14 key (AZ, Vig): {key14}")

# Check if it's periodic with period 7
if key14[:7] == key14[7:]:
    print(f"    *** PERIODIC! period-14 key = {key14[:7]} repeated ***")
else:
    print(f"    First half:  {key14[:7]}")
    print(f"    Second half: {key14[7:]}")
    # Check char-by-char
    matches = sum(1 for i in range(7) if key14[i] == key14[i+7])
    print(f"    {matches}/7 positions match between halves")

pt14 = vig_decrypt(CT, key14)
print(f"  PT (period 14): {pt14}")
print(f"  qg: {qg_score(pt14):+.3f}")

# ═══════════════════════════════════════════════════════════════════════════
# 10. HILL CLIMBING — Period 7
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("10. HILL CLIMBING — Period 7, AZ Vigenère")
print(f"{'='*80}")

import random

def hill_climb_vig(ct, period, alphabet, iterations=50000, restarts=20):
    best_overall_score = -999
    best_overall_key = ""
    best_overall_pt = ""

    for restart in range(restarts):
        # Start from best chi-squared key
        key = list(best_keys_az[0][2]) if restart == 0 else [random.choice(alphabet) for _ in range(period)]

        pt = vig_decrypt(ct, ''.join(key), alphabet)
        current_score = qg_score(pt)

        for it in range(iterations):
            # Mutate one position
            pos = random.randint(0, period - 1)
            old_char = key[pos]
            new_char = random.choice(alphabet)
            if new_char == old_char:
                continue

            key[pos] = new_char
            new_pt = vig_decrypt(ct, ''.join(key), alphabet)
            new_score = qg_score(new_pt)

            if new_score > current_score:
                current_score = new_score
                pt = new_pt
            else:
                key[pos] = old_char

        if current_score > best_overall_score:
            best_overall_score = current_score
            best_overall_key = ''.join(key)
            best_overall_pt = pt

    return best_overall_key, best_overall_score, best_overall_pt

key_hc, score_hc, pt_hc = hill_climb_vig(CT, 7, AZ, iterations=80000, restarts=30)
print(f"  Best key: {key_hc}")
print(f"  Best qg:  {score_hc:+.3f}")
print(f"  Best PT:  {pt_hc}")

# Also try Beaufort
print(f"\n  Hill climbing — Beaufort:")
def hill_climb_beau(ct, period, alphabet, iterations=50000, restarts=20):
    best_score = -999
    best_key = ""
    best_pt = ""

    for restart in range(restarts):
        key = list(best_keys_beau[0][2]) if restart == 0 else [random.choice(alphabet) for _ in range(period)]
        pt = beau_decrypt(ct, ''.join(key), alphabet)
        current_score = qg_score(pt)

        for it in range(iterations):
            pos = random.randint(0, period - 1)
            old_char = key[pos]
            new_char = random.choice(alphabet)
            if new_char == old_char:
                continue
            key[pos] = new_char
            new_pt = beau_decrypt(ct, ''.join(key), alphabet)
            new_score = qg_score(new_pt)
            if new_score > current_score:
                current_score = new_score
                pt = new_pt
            else:
                key[pos] = old_char

        if current_score > best_score:
            best_score = current_score
            best_key = ''.join(key)
            best_pt = pt

    return best_key, best_score, best_pt

key_beau, score_beau, pt_beau = hill_climb_beau(CT, 7, AZ, iterations=80000, restarts=30)
print(f"  Best key: {key_beau}")
print(f"  Best qg:  {score_beau:+.3f}")
print(f"  Best PT:  {pt_beau}")

# Also try KA alphabet
print(f"\n  Hill climbing — Vig/KA:")
key_ka, score_ka, pt_ka = hill_climb_vig(CT, 7, KA, iterations=80000, restarts=30)
print(f"  Best key: {key_ka}")
print(f"  Best qg:  {score_ka:+.3f}")
print(f"  Best PT:  {pt_ka}")

# ═══════════════════════════════════════════════════════════════════════════
# 11. NAMED KEYWORD CANDIDATES
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("11. NAMED KEYWORDS (all lengths)")
print(f"{'='*80}")

NAMED_KEYS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN", "SCHEIDT",
    "BERLIN", "CLOCK", "EAST", "NORTH", "LIGHT", "ANTIPODES", "MEDUSA",
    "ENIGMA", "VIGENERE", "CIPHER", "LUCIFER", "MASONIC", "TEMPLAR",
    "EQUINOX", "SOLSTICE", "COMPASS", "MERCURY", "SECRETS",
    "ILLUSION", "LANGLEY", "BURIED", "PASSAGE", "IQLUSION",
    "OBSCURA", "UNDERGRUUND", "UNDERGROUND", "DYEARLYHOH", "LAYERTWO",
    "HORIZON", "YELLOWED", "BETWEEN", "TOMBKIN", "HOWARDCARTER",
]

results_named = []
for kw in NAMED_KEYS:
    for an, al in [("AZ", AZ), ("KA", KA)]:
        for cn, cf in [("VIG", vig_decrypt), ("BEAU", beau_decrypt), ("VBEAU", varbeau_decrypt)]:
            pt = cf(CT, kw, al)
            score = qg_score(pt)
            results_named.append((score, cn, kw, an, pt))

results_named.sort(key=lambda x: -x[0])
print(f"\n  Top 25:")
for score, cn, kw, an, pt in results_named[:25]:
    print(f"    {score:+.3f} {cn}/{kw}/{an}: {pt[:65]}...")

# ═══════════════════════════════════════════════════════════════════════════
# 12. AUTOKEY ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("12. AUTOKEY VIGENÈRE (key primes the autokey)")
print(f"{'='*80}")

def autokey_decrypt(ct, primer, alphabet=AZ):
    """Autokey Vigenère: key = primer + plaintext."""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        ki = alphabet.index(key[i]) if i < len(key) else alphabet.index(pt[i - len(primer)])
        ci = alphabet.index(c)
        pi = (ci - ki) % len(alphabet)
        pt.append(alphabet[pi])
    return ''.join(pt)

for primer in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "K", "KR", "KRY", "KRYP",
               "A", "AB", "ABC", "ABSCISS", "BERLIN", "SHADOW"]:
    for alph_name, alph in [("AZ", AZ)]:
        pt = autokey_decrypt(CT, primer, alph)
        score = qg_score(pt)
        if score > -8.5:
            print(f"  Primer={primer}/{alph_name}: qg={score:+.3f}  PT={pt}")

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("SUMMARY")
print(f"{'='*80}")
print(f"""
  CT: {CT}
  Length: {len(CT)}
  IC: {ic(CT):.4f}

  Period 7 IC: 0.0547 (significant spike)
  Period 14 IC: 0.0558 (even higher — 2×7)

  Best Vig/AZ key (chi²):     {best_keys_az[0][2]} → qg={best_keys_az[0][0]:+.3f}
  Best Beau/AZ key (chi²):    {best_keys_beau[0][2]} → qg={best_keys_beau[0][0]:+.3f}
  Best Vig/AZ key (hill climb): {key_hc} → qg={score_hc:+.3f}
  Best Beau/AZ key (hill climb): {key_beau} → qg={score_beau:+.3f}
  Best Vig/KA key (hill climb): {key_ka} → qg={score_ka:+.3f}
""")
