#!/usr/bin/env python3
"""
Cipher: YAR grille
Family: yar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Attack the user-provided YAR-modified K4 CT with all methods.

User's modified CT (9 YAR positions replaced with tableau values):
OBKKUOXOGHULBSOLIFBBWFLJVQQPUNGKSSOTWTQSJQSSEKZZWFTJKLUDIQWINFBNRPVTTMZFPKWGDKZXTJCDIGKUHUXUEKCCD
"""

import sys, json, os
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as ORIGINAL_K4, CRIB_WORDS

K4_MODIFIED = "OBKKUOXOGHULBSOLIFBBWFLJVQQPUNGKSSOTWTQSJQSSEKZZWFTJKLUDIQWINFBNRPVTTMZFPKWGDKZXTJCDIGKUHUXUEKCCD"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "EAST", "NORTH",
    "LIGHT", "ANTIPODES", "MEDUSA", "ENIGMA", "UNDERGRUUND",
    "UNDERGROUND", "KRYPTOSABCDE", "YESTHEWONDERFULT",
]

print("=" * 80)
print("ATTACK ON USER-PROVIDED YAR-MODIFIED K4")
print("=" * 80)
print(f"\nOriginal: {ORIGINAL_K4}")
print(f"Modified: {K4_MODIFIED}")
print(f"Length: {len(K4_MODIFIED)}")

# Verify changes
diffs = [(i, ORIGINAL_K4[i], K4_MODIFIED[i]) for i in range(97) if ORIGINAL_K4[i] != K4_MODIFIED[i]]
print(f"\n{len(diffs)} replacements: {[(p, f'{o}→{n}') for p,o,n in diffs]}")

# Basic stats
from collections import Counter
freq = Counter(K4_MODIFIED)
print(f"\nFrequency: {dict(sorted(freq.items(), key=lambda x: -x[1]))}")
print(f"Unique letters: {len(freq)}")

# IC
n = len(K4_MODIFIED)
ic = sum(f*(f-1) for f in freq.values()) / (n*(n-1))
print(f"IC: {ic:.4f} (random: 0.0385, English: 0.0667)")

# Chi-squared vs English
eng_freq = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074,
}
chi2 = sum((freq.get(c, 0) - n * eng_freq[c]/100)**2 / (n * eng_freq[c]/100) for c in AZ)
print(f"Chi² vs English: {chi2:.1f}")

def vig_decrypt(ct, key, alphabet):
    return ''.join(alphabet[(alphabet.index(c) - alphabet.index(key[i%len(key)])) % len(alphabet)]
                   for i, c in enumerate(ct))

def beau_decrypt(ct, key, alphabet):
    return ''.join(alphabet[(alphabet.index(key[i%len(key)]) - alphabet.index(c)) % len(alphabet)]
                   for i, c in enumerate(ct))

def varbeau_decrypt(ct, key, alphabet):
    return ''.join(alphabet[(alphabet.index(c) + alphabet.index(key[i%len(key)])) % len(alphabet)]
                   for i, c in enumerate(ct))

# Load quadgrams
QG = {}
qg_path = os.path.join('data', 'english_quadgrams.json')
if os.path.exists(qg_path):
    with open(qg_path) as f:
        QG = json.load(f)
    print(f"Loaded {len(QG)} quadgrams")

import math
def qg_score(text):
    if not QG:
        return -99
    total = 0
    floor = -10.0
    for i in range(len(text) - 3):
        gram = text[i:i+4]
        total += QG.get(gram, floor)
    return total / max(1, len(text) - 3)

# Crib check
CRIBS = [(start, start + len(word) - 1, word) for start, word in CRIB_WORDS]

def check_cribs(text):
    hits = 0
    for start, end, word in CRIBS:
        if text[start:end+1] == word:
            hits += 1
    return hits

# ── Main attack loop ──
print(f"\n{'='*80}")
print("KEYWORD DECRYPTIONS (Vig/Beau/VarBeau × AZ/KA)")
print(f"{'='*80}")

results = []
for keyword in KEYWORDS:
    for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
        for cipher_name, cipher_fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt), ("VBEAU", varbeau_decrypt)]:
            pt = cipher_fn(K4_MODIFIED, keyword, alph)
            score = qg_score(pt)
            cribs = check_cribs(pt)
            results.append((cipher_name, keyword, alph_name, pt, score, cribs))

# Sort by qg score
results.sort(key=lambda x: -x[4])

print(f"\nTop 20 by quadgram score:")
for cipher_name, keyword, alph_name, pt, score, cribs in results[:20]:
    crib_flag = " *** CRIB ***" if cribs else ""
    print(f"  {score:+.3f} {cipher_name}/{keyword}/{alph_name}: {pt}{crib_flag}")

# Check for crib hits specifically
crib_results = [r for r in results if r[5] > 0]
if crib_results:
    print(f"\n*** CRIB HITS: {len(crib_results)} ***")
    for cipher_name, keyword, alph_name, pt, score, cribs in crib_results:
        print(f"  {cipher_name}/{keyword}/{alph_name}: {pt} (cribs: {cribs}, qg: {score:+.3f})")

# ── Crib dragging ──
print(f"\n{'='*80}")
print("CRIB DRAGGING — Vig key at each position")
print(f"{'='*80}")

for crib_word in ["EASTNORTHEAST", "BERLINCLOCK", "YESWONDERFUL", "YESTHEWONDER"]:
    best_key_score = -99
    best_pos = -1
    best_key = ""
    for pos in range(len(K4_MODIFIED) - len(crib_word) + 1):
        ct_slice = K4_MODIFIED[pos:pos+len(crib_word)]
        key = ''.join(AZ[(AZ.index(c) - AZ.index(p)) % 26] for c, p in zip(ct_slice, crib_word))
        # Check if key is periodic
        for period in range(1, len(key)):
            if all(key[j] == key[j % period] for j in range(len(key))):
                # Found a periodic key!
                print(f"  {crib_word} at pos {pos}: key period {period}, key='{key[:period]}' → check: ", end="")
                # Decrypt full CT with this periodic key
                full_pt = vig_decrypt(K4_MODIFIED, key[:period], AZ)
                score = qg_score(full_pt)
                cribs = check_cribs(full_pt)
                print(f"qg={score:+.3f}, cribs={cribs}")
                if score > -6.5:
                    print(f"    PT: {full_pt}")
                break

# ── Caesar shifts ──
print(f"\n{'='*80}")
print("CAESAR SHIFTS (shift 0-25)")
print(f"{'='*80}")

for shift in range(26):
    pt = ''.join(AZ[(AZ.index(c) - shift) % 26] for c in K4_MODIFIED)
    score = qg_score(pt)
    if score > -8.0:
        print(f"  Shift {shift:2d}: {pt} (qg: {score:+.3f})")

# ── Reverse ──
print(f"\n{'='*80}")
print("REVERSE + DECRYPT")
print(f"{'='*80}")

rev = K4_MODIFIED[::-1]
for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for alph_name, alph in [("AZ", AZ)]:
        for cipher_name, cipher_fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt)]:
            pt = cipher_fn(rev, keyword, alph)
            score = qg_score(pt)
            cribs = check_cribs(pt)
            print(f"  {cipher_name}/{keyword}: qg={score:+.3f}, cribs={cribs}")
            if score > -7.0 or cribs > 0:
                print(f"    PT: {pt}")

# ── Word search in all decryptions ──
print(f"\n{'='*80}")
print("ENGLISH WORD SEARCH IN ALL DECRYPTIONS")
print(f"{'='*80}")

LONG_WORDS = ["EAST", "NORTH", "BERLIN", "CLOCK", "SHADOW", "UNDERGROUND", "SLOWLY",
              "WONDERFUL", "THINGS", "INVISIBLE", "BURIED", "TOMB", "LIGHT",
              "BETWEEN", "SUBTLE", "SHADING", "ABSENCE",
              "DESPERATE", "EMERGE", "ANYTHING", "ILLUSION"]

for cipher_name, keyword, alph_name, pt, score, cribs in results:
    found_words = [w for w in LONG_WORDS if w in pt]
    if found_words:
        print(f"  {cipher_name}/{keyword}/{alph_name}: found {found_words} (qg: {score:+.3f})")
        print(f"    PT: {pt}")

# ── IC at various periods ──
print(f"\n{'='*80}")
print("IC AT VARIOUS PERIODS (looking for periodicity)")
print(f"{'='*80}")

for period in range(1, 16):
    columns = ['' for _ in range(period)]
    for i, c in enumerate(K4_MODIFIED):
        columns[i % period] += c
    avg_ic = sum(
        sum(f*(f-1) for f in Counter(col).values()) / max(1, len(col)*(len(col)-1))
        for col in columns
    ) / period
    bar = '#' * int(avg_ic * 500)
    print(f"  Period {period:2d}: IC={avg_ic:.4f} {bar}")

# ── Comparison: my tableau values vs user's ──
print(f"\n{'='*80}")
print("MAPPING COMPARISON: My computation vs User's values")
print(f"{'='*80}")

TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
    "AABCDEFGHIJLMNQUVWXZKRYPTOSABCD",
    "BBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",
    "CCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",
    "DDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",
    "EEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",
    "FFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",
    "GGHIJLMNQUVWXZKRYPTOSABCDEFGHIJ",
    "HHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",
    "IIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",
    "JJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",
    "KKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",
    "LLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",
    "MMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",
    "NNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",
    "OOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",
    "PPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",
    "QQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",
    "RRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",
    "SSABCDEFGHIJLMNQUVWXZKRYPTOSABC",
    "TTOSABCDEFGHIJLMNQUVWXZKRYPTOSA",
    "UUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",
    "VVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",
    "WWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",
    "XXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",
    "YYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
]

K4_GRID_START = 771
GRID_WIDTH = 31

yar_positions = {3: 'R', 23: 'R', 28: 'R', 49: 'A', 57: 'A', 64: 'Y', 90: 'A', 95: 'A', 96: 'R'}

print(f"{'Pos':>4} {'Orig':>5} {'User':>5} {'MyTab':>6} {'Grid':>8} {'Match':>6}")
for pos in sorted(yar_positions.keys()):
    grid_pos = K4_GRID_START + pos
    row = grid_pos // GRID_WIDTH
    col = grid_pos % GRID_WIDTH
    my_tab = TABLEAU_ROWS[row][col] if row < len(TABLEAU_ROWS) else '?'
    user_val = K4_MODIFIED[pos]
    orig_val = ORIGINAL_K4[pos]
    match = "YES" if my_tab == user_val else "NO"
    print(f"{pos:4d} {orig_val:>5} {user_val:>5} {my_tab:>6}  ({row},{col:2d}) {match:>6}")

print(f"\nIf they differ, user may be using a different row/col mapping or different tableau.")

print(f"\n{'='*80}")
print("DONE")
print(f"{'='*80}")
