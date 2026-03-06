#!/usr/bin/env python3
"""
Solve T15 with hint: two-layer, undo transposition (width 6) then Vigenere (period 8).
720 column permutations × 8 Caesar solves per column = fast.
"""

import json
from collections import Counter
from itertools import permutations

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT = "VIWFUVDUJWVVTCVDWYAQCNRXEEIHSEVPUSIXNRWKHHLAIPHSEXZOEMUCRIHTHTIEPIEXHLIIIACHMVIXHKZLWXDFDJRFVGVZLRLWGDFULNVILRTYHKPUYHYX"

# Load quadgram scorer
with open("data/english_quadgrams.json") as f:
    QG = json.load(f)
QG_FLOOR = min(QG.values()) - 2.0

def qg_score(text: str) -> float:
    if len(text) < 4:
        return -99.0
    return sum(QG.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3)) / (len(text) - 3)

def ic(text: str) -> float:
    n = len(text)
    if n <= 1:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

# English letter frequencies for chi-squared
ENG_FREQ = [0.082,0.015,0.028,0.043,0.127,0.022,0.020,0.061,0.070,0.002,
            0.008,0.040,0.024,0.067,0.075,0.019,0.001,0.060,0.063,0.091,
            0.028,0.010,0.024,0.002,0.020,0.001]

def chi_sq(text: str) -> float:
    """Lower = more English-like."""
    n = len(text)
    if n == 0:
        return 9999.0
    freq = Counter(text)
    return sum((freq.get(ALPHA[i], 0) - n * ENG_FREQ[i]) ** 2 / (n * ENG_FREQ[i])
               for i in range(26))

def best_caesar_shift(text: str) -> tuple[int, float]:
    """Find the Caesar shift that minimizes chi-squared."""
    best_shift, best_chi = 0, 9999.0
    for shift in range(26):
        decrypted = "".join(ALPHA[(ALPHA.index(c) - shift) % 26] for c in text)
        cs = chi_sq(decrypted)
        if cs < best_chi:
            best_chi = cs
            best_shift = shift
    return best_shift, best_chi

def columnar_decrypt(ct: str, key_order: list[int]) -> str:
    width = len(key_order)
    nrows = len(ct) // width
    remainder = len(ct) % width
    col_lengths = [nrows] * width
    for i in range(remainder):
        col_lengths[key_order[i]] += 1
    cols = [""] * width
    pos = 0
    for col in key_order:
        cols[col] = ct[pos:pos + col_lengths[col]]
        pos += col_lengths[col]
    pt = []
    for r in range(nrows + (1 if remainder else 0)):
        for c in range(width):
            if r < len(cols[c]):
                pt.append(cols[c][r])
    return "".join(pt)

def vigenere_decrypt(ct: str, key: str) -> str:
    return "".join(ALPHA[(ALPHA.index(c) - ALPHA.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(ct))

# Load dictionary for key validation
with open("wordlists/english.txt") as f:
    word_set = set(w.strip().upper() for w in f if len(w.strip()) == 8 and w.strip().isalpha())
print(f"Loaded {len(word_set)} 8-letter dictionary words")

WIDTH = 6
PERIOD = 8

print(f"\nWidth {WIDTH}: testing {len(list(permutations(range(WIDTH))))} column permutations")
print(f"For each, solve Vigenere period {PERIOD} by frequency analysis\n")

best_results = []

for perm in permutations(range(WIDTH)):
    key_order = list(perm)
    inter = columnar_decrypt(CT, key_order)

    # Solve each of 8 Vigenere columns by best Caesar shift
    shifts = []
    total_chi = 0
    for col_idx in range(PERIOD):
        col_text = inter[col_idx::PERIOD]
        shift, chi = best_caesar_shift(col_text)
        shifts.append(shift)
        total_chi += chi

    # Reconstruct Vigenere key from shifts
    vig_key = "".join(ALPHA[s] for s in shifts)

    # Decrypt
    pt = vigenere_decrypt(inter, vig_key)
    score = qg_score(pt)

    # Check if key is a dictionary word
    is_word = vig_key in word_set

    if score > -5.0 or is_word:
        best_results.append((score, perm, vig_key, pt, is_word))

# Sort by score descending
best_results.sort(key=lambda x: -x[0])

print(f"{'Score':>7}  {'Perm':<20}  {'Vig Key':<10}  {'Dict?':<6}  Plaintext")
print(f"{'─'*7}  {'─'*20}  {'─'*10}  {'─'*6}  {'─'*50}")
for score, perm, key, pt, is_word in best_results[:15]:
    marker = "YES" if is_word else ""
    print(f"{score:>7.3f}  {str(list(perm)):<20}  {key:<10}  {marker:<6}  {pt[:50]}...")

if best_results:
    score, perm, key, pt, is_word = best_results[0]
    print(f"\n{'=' * 72}")
    print(f"BEST RESULT")
    print(f"{'=' * 72}")
    print(f"  Score:      {score:.3f}")
    print(f"  Col perm:   {list(perm)}")
    print(f"  Vig key:    {key}  (dictionary word: {is_word})")
    print(f"  IC of PT:   {ic(pt):.4f}")
    print(f"  Plaintext:  {pt[:60]}")
    print(f"              {pt[60:]}")
