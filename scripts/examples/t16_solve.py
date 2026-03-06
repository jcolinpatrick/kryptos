#!/usr/bin/env python3
"""
Blind solve of training cipher T16.
Step 1: Diagnostics (IC, frequency, Kasiski)
Step 2: Attack based on diagnosis
"""

import json
from collections import Counter
from itertools import permutations
from functools import reduce
from math import gcd

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT = "YIVGXDNRBZUVGGHTLJPQLVTFNVAJQBFURTCMUPTAWCVSGHJLUKZKGN"

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

ENG_FREQ = [0.082,0.015,0.028,0.043,0.127,0.022,0.020,0.061,0.070,0.002,
            0.008,0.040,0.024,0.067,0.075,0.019,0.001,0.060,0.063,0.091,
            0.028,0.010,0.024,0.002,0.020,0.001]

def chi_sq(text: str) -> float:
    n = len(text)
    if n == 0:
        return 9999.0
    freq = Counter(text)
    return sum((freq.get(ALPHA[i], 0) - n * ENG_FREQ[i]) ** 2 / (n * ENG_FREQ[i])
               for i in range(26))

def best_caesar_shift(text: str) -> tuple[int, float]:
    best_shift, best_chi = 0, 9999.0
    for shift in range(26):
        decrypted = "".join(ALPHA[(ALPHA.index(c) - shift) % 26] for c in text)
        cs = chi_sq(decrypted)
        if cs < best_chi:
            best_chi = cs
            best_shift = shift
    return best_shift, best_chi

def vigenere_decrypt(ct: str, key: str) -> str:
    return "".join(ALPHA[(ALPHA.index(c) - ALPHA.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(ct))

def beaufort_decrypt(ct: str, key: str) -> str:
    return "".join(ALPHA[(ALPHA.index(key[i % len(key)]) - ALPHA.index(c)) % 26]
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
total = len(CT)
top5 = sum(freq.get(c, 0) for c in "ETAOI") / total * 100

print(f"  Length: {total}")
print(f"  IC: {ic_val:.4f}  (English ~0.067, random ~0.038)")
print(f"  Top-5 (ETAOI): {top5:.1f}%  (English ~43.5%)")

# Top frequencies
sorted_freq = sorted(freq.items(), key=lambda x: -x[1])
print(f"\n  Top letters: {', '.join(f'{l}={c}' for l, c in sorted_freq[:8])}")

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
    # Factor analysis
    from collections import defaultdict
    factor_counts = defaultdict(int)
    for s in all_spacings:
        for f in range(2, s + 1):
            if s % f == 0:
                factor_counts[f] += 1
    top_factors = sorted(factor_counts.items(), key=lambda x: -x[1])[:6]
    print(f"  Top factors: {', '.join(f'{f}(×{c})' for f, c in top_factors)}")
else:
    print(f"  Kasiski: {len(all_spacings)} spacings")

# Periodic IC analysis
print(f"\n  Periodic IC analysis:")
for period in range(2, 13):
    col_ics = []
    for offset in range(period):
        col = CT[offset::period]
        if len(col) > 3:
            col_ics.append(ic(col))
    avg = sum(col_ics) / len(col_ics) if col_ics else 0
    marker = " <-- SIGNAL" if avg > 0.060 else ""
    print(f"    Period {period:2d}: avg column IC = {avg:.4f}{marker}")

# ── DIAGNOSIS ──
print(f"\n  DIAGNOSIS:")
if ic_val > 0.060:
    print(f"    IC near English --> transposition or monoalphabetic")
elif ic_val > 0.050:
    print(f"    IC moderately depressed --> short polyalphabetic or TWO-LAYER")
elif ic_val > 0.042:
    print(f"    IC in danger zone --> polyalphabetic (p=5-12) or TWO-LAYER")
else:
    print(f"    IC near random --> long key, fractionation, or heavy layering")

# ── STEP 2: SINGLE-LAYER ATTACKS ──
print(f"\n{'=' * 72}")
print("STEP 2: SINGLE-LAYER ATTACKS")
print("=" * 72)

# 2A: Caesar
print("\n  2A: Caesar (26 shifts)")
best_caesar = (-99, "", 0)
for shift in range(26):
    pt = "".join(ALPHA[(ALPHA.index(c) - shift) % 26] for c in CT)
    s = qg_score(pt)
    if s > best_caesar[0]:
        best_caesar = (s, pt, shift)
print(f"    Best: shift={best_caesar[2]}, score={best_caesar[0]:.3f}, {best_caesar[1][:40]}...")

# 2B: Vigenere + Beaufort with dictionary (periods 3-10)
print("\n  2B: Vigenere/Beaufort dictionary attack (periods 3-10)")
with open("wordlists/english.txt") as f:
    words = [w.strip().upper() for w in f if 3 <= len(w.strip()) <= 10
             and w.strip().isalpha() and all(c in ALPHA for c in w.strip().upper())]
print(f"    {len(words)} dictionary words loaded")

best_vig = (-99, "", "")
best_beau = (-99, "", "")
for word in words:
    pt_v = vigenere_decrypt(CT, word)
    s_v = qg_score(pt_v)
    if s_v > best_vig[0]:
        best_vig = (s_v, pt_v, word)

    pt_b = beaufort_decrypt(CT, word)
    s_b = qg_score(pt_b)
    if s_b > best_beau[0]:
        best_beau = (s_b, pt_b, word)

print(f"    Vigenere best:  key={best_vig[2]}, score={best_vig[0]:.3f}, {best_vig[1][:40]}...")
print(f"    Beaufort best:  key={best_beau[2]}, score={best_beau[0]:.3f}, {best_beau[1][:40]}...")

# 2C: Columnar transposition (widths 3-9)
print("\n  2C: Columnar transposition (widths 3-9)")
best_trans = (-99, "", [], 0)
for width in range(3, 10):
    for perm in permutations(range(width)):
        pt = columnar_decrypt(CT, list(perm))
        s = qg_score(pt)
        if s > best_trans[0]:
            best_trans = (s, pt, list(perm), width)
print(f"    Best: width={best_trans[3]}, perm={best_trans[2]}, score={best_trans[0]:.3f}")
print(f"    {best_trans[1][:50]}...")

# ── Check if any single-layer attack succeeded ──
all_best = [
    ("Caesar", best_caesar[0], best_caesar[1]),
    ("Vigenere", best_vig[0], best_vig[1]),
    ("Beaufort", best_beau[0], best_beau[1]),
    ("Transposition", best_trans[0], best_trans[1]),
]
all_best.sort(key=lambda x: -x[1])

print(f"\n  Single-layer scoreboard:")
for name, score, pt in all_best:
    marker = " *** SOLVED" if score > -4.5 else ""
    print(f"    {name:<15} {score:>7.3f}  {pt[:40]}...{marker}")

winner = all_best[0]
if winner[1] > -4.5:
    print(f"\n  SINGLE-LAYER SOLVE: {winner[0]} with score {winner[1]:.3f}")
    print(f"  PT: {winner[2]}")
else:
    # ── STEP 3: TWO-LAYER DECOMPOSITION ──
    print(f"\n{'=' * 72}")
    print("STEP 3: TWO-LAYER DECOMPOSITION")
    print("=" * 72)
    print("  No single-layer attack scored above -4.5. Trying two-layer.")

    best_two = (-99, "", [], "", "", 0, 0)  # score, pt, perm, vig_key, mode, width, period

    for width in range(4, 8):
        print(f"\n  Width {width} ({len(list(permutations(range(width))))} perms):")
        for perm in permutations(range(width)):
            inter = columnar_decrypt(CT, list(perm))

            # Find best period by column IC
            for period in range(3, 13):
                col_ics = []
                for offset in range(period):
                    col = inter[offset::period]
                    if len(col) > 3:
                        col_ics.append(ic(col))
                avg_ic = sum(col_ics) / len(col_ics) if col_ics else 0

                if avg_ic > 0.055:
                    # Solve Vigenere analytically
                    shifts = []
                    for col_idx in range(period):
                        col_text = inter[col_idx::period]
                        shift, _ = best_caesar_shift(col_text)
                        shifts.append(shift)
                    vig_key = "".join(ALPHA[s] for s in shifts)

                    # Try Vigenere
                    pt_v = vigenere_decrypt(inter, vig_key)
                    s_v = qg_score(pt_v)
                    if s_v > best_two[0]:
                        best_two = (s_v, pt_v, list(perm), vig_key, "Vig", width, period)

                    # Try Beaufort
                    beau_key = "".join(ALPHA[(26 - s) % 26] for s in shifts)
                    pt_b = beaufort_decrypt(inter, beau_key)
                    s_b = qg_score(pt_b)
                    if s_b > best_two[0]:
                        best_two = (s_b, pt_b, list(perm), beau_key, "Beau", width, period)

        # Report best at this width
        if best_two[5] == width:
            print(f"    Best: perm={best_two[2]}, {best_two[4]} key={best_two[3]}, "
                  f"period={best_two[6]}, score={best_two[0]:.3f}")

    score, pt, perm, key, mode, width, period = best_two
    print(f"\n{'=' * 72}")
    print(f"BEST TWO-LAYER RESULT")
    print(f"{'=' * 72}")
    print(f"  Score:      {score:.3f}")
    print(f"  Width:      {width}, perm: {perm}")
    print(f"  Sub type:   {mode}, key: {key} (period {period})")
    print(f"  IC of PT:   {ic(pt):.4f}")
    print(f"  Plaintext:  {pt}")
