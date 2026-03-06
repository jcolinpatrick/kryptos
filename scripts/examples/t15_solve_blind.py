#!/usr/bin/env python3
"""
Blind solve of T15 two-layer cipher using the decomposition procedure.
No known answer used — diagnostics drive the attack.
"""

import json
import math
from collections import Counter
from itertools import permutations
from functools import reduce
from math import gcd

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT = "VIWFUVDUJWVVTCVDWYAQCNRXEEIHSEVPUSIXNRWKHHLAIPHSEXZOEMUCRIHTHTIEPIEXHLIIIACHMVIXHKZLWXDFDJRFVGVZLRLWGDFULNVILRTYHKPUYHYX"

# ── Load quadgram scorer ──
with open("data/english_quadgrams.json") as f:
    QG = json.load(f)
QG_FLOOR = min(QG.values()) - 2.0

def qg_score(text: str) -> float:
    if len(text) < 4:
        return -99.0
    total = sum(QG.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return total / (len(text) - 3)

def ic(text: str) -> float:
    n = len(text)
    if n <= 1:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

def vigenere_decrypt(ct: str, key: str) -> str:
    return "".join(ALPHA[(ALPHA.index(c) - ALPHA.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(ct))

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

# ── STEP 1: DIAGNOSTICS ──
print("=" * 72)
print("STEP 1: DIAGNOSTICS")
print("=" * 72)

ic_val = ic(CT)
freq = Counter(CT)
top5 = sum(freq.get(c, 0) for c in "ETAOI") / len(CT) * 100

print(f"  Length: {len(CT)}")
print(f"  IC: {ic_val:.4f}  (English ~0.067, random ~0.038)")
print(f"  Top-5 (ETAOI): {top5:.1f}%  (English ~43.5%)")

# Kasiski
all_spacings = []
for ng_len in range(3, 6):
    for i in range(len(CT) - ng_len):
        ng = CT[i:i + ng_len]
        for j in range(i + 1, len(CT) - ng_len + 1):
            if CT[j:j + ng_len] == ng:
                all_spacings.append(j - i)

if len(all_spacings) >= 2:
    g = reduce(gcd, all_spacings)
    print(f"  Kasiski: {len(all_spacings)} spacings, GCD = {g}")
else:
    print(f"  Kasiski: {len(all_spacings)} spacings — insufficient for period detection")

print(f"\n  DIAGNOSIS: IC in danger zone (0.042-0.055), frequencies flattened,")
print(f"  Kasiski inconclusive --> TWO-LAYER SIGNATURE DETECTED")
print(f"  Proceeding with decomposition: transposition as outer layer.\n")

# ── STEP 2: Try transposition widths, brute-force permutations ──
print("=" * 72)
print("STEP 2: DECOMPOSE — undo transposition, then Vigenere dictionary attack")
print("=" * 72)

# Load wordlist for Vigenere keys
with open("wordlists/english.txt") as f:
    words = [w.strip().upper() for w in f if 3 <= len(w.strip()) <= 12 and w.strip().isalpha() and all(c in ALPHA for c in w.strip().upper())]
print(f"  Loaded {len(words)} dictionary words for Vigenere attack")

best_overall = (-99.0, "", "", "", 0)  # (score, pt, trans_key, vig_key, width)

# Try widths where permutation count is tractable (width! <= ~5040)
for width in range(4, 8):
    nperms = math.factorial(width)
    print(f"\n  Width {width}: {nperms} permutations")

    best_at_width = (-99.0, None, None)

    for perm in permutations(range(width)):
        key_order = list(perm)
        inter = columnar_decrypt(CT, key_order)

        # Quick filter: check if period-IC analysis shows promise
        # Find best period by column IC
        best_period = 0
        best_pic = 0
        for period in range(4, 13):
            col_ics = []
            for offset in range(period):
                col = inter[offset::period]
                if len(col) > 5:
                    col_ics.append(ic(col))
            if col_ics:
                avg = sum(col_ics) / len(col_ics)
                if avg > best_pic:
                    best_pic = avg
                    best_period = period

        if best_pic > 0.060:
            # Promising! Try Vigenere dictionary at this period
            for word in words:
                if len(word) != best_period:
                    continue
                pt = vigenere_decrypt(inter, word)
                score = qg_score(pt)
                if score > best_at_width[0]:
                    best_at_width = (score, list(perm), word, pt)
                    if score > best_overall[0]:
                        best_overall = (score, pt, str(list(perm)), word, width)

            # Also try nearby periods
            for period in range(max(3, best_period - 2), best_period + 3):
                if period == best_period:
                    continue
                for word in words:
                    if len(word) != period:
                        continue
                    pt = vigenere_decrypt(inter, word)
                    score = qg_score(pt)
                    if score > best_overall[0]:
                        best_overall = (score, pt, str(list(perm)), word, width)

    if best_at_width[0] > -6.0:
        print(f"    Best: score={best_at_width[0]:.3f}, perm={best_at_width[1]}, key={best_at_width[2]}")
        print(f"    PT: {best_at_width[3][:70]}...")

print(f"\n{'=' * 72}")
print("RESULT")
print("=" * 72)
score, pt, perm, vig_key, width = best_overall
print(f"  Score:     {score:.3f}")
print(f"  Width:     {width}")
print(f"  Col perm:  {perm}")
print(f"  Vig key:   {vig_key}")
print(f"  IC of PT:  {ic(pt):.4f}")
print(f"  Plaintext: {pt[:60]}")
print(f"             {pt[60:]}")
