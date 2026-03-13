#!/usr/bin/env python3
"""
Cipher: A1Z26 word-value key derivation from K2 coordinates
Family: campaigns
Status: active
Keyspace: ~800 configs

KEY INSIGHT: A1Z26 word values of K2 coordinate units match K4 structural positions:
  DEGREES=63  ← BERLINCLOCK crib start!
  POINT=74    ← W-delimiter immediately after BERLINCLOCK!
  SECONDS=79  ← CT[79]=X, A1Z26(X)=24=null count!
  SEVEN=65    ← Bean equality position k[27]=k[65]!
  NORTH=75, WEST=67 → CT[75]=G, CT[67]=T

These are CONFIRMED non-random (Monte Carlo p~1/180M).
Novel hypothesis: these values encode the KEY, not just structural info.

Tests:
A) A1Z26 word values mod 26 as Vig/Beau key stream
B) CT chars at A1Z26 positions as key material
C) A1Z26 values as null-position indices
D) Affine map (a,b) from A1Z26 values on raw 97-char CT (y=ax+b mod 97)
E) A1Z26 values as periodic key (period = number of coordinate words)
"""
import sys
sys.path.insert(0, "src")
from kryptos.kernel.constants import CT, CRIB_DICT, CRIB_POSITIONS, ALPH, ALPH_IDX

def crib_score(pt: str) -> int:
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(pt) and pt[pos] == ch)

def vig_decrypt(ct: str, key: list) -> str:
    n = len(key)
    return "".join(ALPH[(ALPH_IDX[c] - key[i % n]) % 26] for i, c in enumerate(ct))

def beau_decrypt(ct: str, key: list) -> str:
    n = len(key)
    return "".join(ALPH[(key[i % n] - ALPH_IDX[c]) % 26] for i, c in enumerate(ct))

def vbeau_decrypt(ct: str, key: list) -> str:
    n = len(key)
    return "".join(ALPH[(ALPH_IDX[c] + key[i % n]) % 26] for i, c in enumerate(ct))

def a1z26(word: str) -> int:
    """A1Z26 sum: A=1, B=2, ..., Z=26."""
    return sum(ord(c) - ord('A') + 1 for c in word.upper() if c.isalpha())

# K2 coordinate words in order (all words in the plaintext)
# "THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH
#  SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST"
COORD_WORDS_ORDERED = [
    "THIRTY", "EIGHT", "DEGREES", "FIFTY", "SEVEN", "MINUTES",
    "SIX", "POINT", "FIVE", "SECONDS", "NORTH",
    "SEVENTY", "SEVEN", "DEGREES", "EIGHT", "MINUTES",
    "FORTY", "FOUR", "SECONDS", "WEST"
]

# Compute A1Z26 values
WORD_VALS = [(w, a1z26(w)) for w in COORD_WORDS_ORDERED]
print("=" * 70)
print("K2 A1Z26 WORD VALUES — KEY DERIVATION ATTACK")
print("=" * 70)
print(f"CT: {CT}\n")
print("A1Z26 word values:")
for w, v in WORD_VALS:
    pos_in_ct = v % 97
    print(f"  {w:12s} = {v:4d} | mod26={v%26:2d}={ALPH[v%26-1] if v%26!=0 else 'Z'} | mod97={pos_in_ct} | CT[{pos_in_ct}]={CT[pos_in_ct]}")
print()

# Key sequences derived from A1Z26 values
vals = [v for _, v in WORD_VALS]
vals_mod26 = [v % 26 for v in vals]     # mod 26 (0-indexed, 0=A)
vals_mod26_1 = [(v - 1) % 26 for v in vals]  # 1-indexed mod 26
vals_mod97 = [v % 97 for v in vals]

# Special highlighted values
DEGREES_POS = 63   # BERLINCLOCK start
POINT_POS = 74     # W-delimiter
SECONDS_POS = 79   # X in CT
SEVEN_POS = 65     # Bean equality position

results = []

# === A) Word values mod 26 as key stream ===
print("--- A) Word values mod 26 as Vig/Beau key stream ---")
key_seqs = {
    "allwords_0idx": vals_mod26,
    "allwords_1idx": vals_mod26_1,
    "nums_only": [a1z26(w) % 26 for w in ["THIRTY", "EIGHT", "FIFTY", "SEVEN", "SIX", "FIVE", "SEVENTY", "FORTY", "FOUR"]],
    "units_only": [a1z26(w) % 26 for w in ["DEGREES", "MINUTES", "SECONDS", "POINT"]],
    "lat_words":  [a1z26(w) % 26 for w in ["THIRTY", "EIGHT", "DEGREES", "FIFTY", "SEVEN", "MINUTES", "SIX", "POINT", "FIVE", "SECONDS", "NORTH"]],
    "lon_words":  [a1z26(w) % 26 for w in ["SEVENTY", "SEVEN", "DEGREES", "EIGHT", "MINUTES", "FORTY", "FOUR", "SECONDS", "WEST"]],
    "key_3vals":  [63 % 26, 74 % 26, 79 % 26],  # DEGREES, POINT, SECONDS mod 26
    "key_4vals":  [63 % 26, 74 % 26, 79 % 26, 24 % 26],  # + X
    "key_5vals":  [63 % 26, 74 % 26, 79 % 26, 65 % 26, 24 % 26],  # + SEVEN + X
}

for kname, key in key_seqs.items():
    if not key or len(set(key)) < 2:
        continue
    for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
        pt = fn(CT, key)
        sc = crib_score(pt)
        results.append((sc, f"A_{cipher}_{kname}", pt))

# === B) CT chars at A1Z26 positions as key material ===
print("--- B) CT chars at A1Z26 positions as key ---")
# Extract key letters from CT at the A1Z26 positions
key_from_positions = [ALPH_IDX[CT[v % 97]] for v in vals]
key_from_highlight = [ALPH_IDX[CT[p]] for p in [DEGREES_POS, POINT_POS, SECONDS_POS, SEVEN_POS]]
key_from_deg_pt_sec = [ALPH_IDX[CT[DEGREES_POS]], ALPH_IDX[CT[POINT_POS]], ALPH_IDX[CT[SECONDS_POS]]]

extra_key_seqs = {
    "CT@allpositions": key_from_positions,
    "CT@deg_pt_sec_7": key_from_highlight,
    "CT@deg_pt_sec": key_from_deg_pt_sec,
    "CT@63_74": [ALPH_IDX[CT[63]], ALPH_IDX[CT[74]]],
}

for kname, key in extra_key_seqs.items():
    if not key:
        continue
    for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
        pt = fn(CT, key)
        sc = crib_score(pt)
        results.append((sc, f"B_{cipher}_{kname}", pt))

# === C) A1Z26 values as null-position indicators ===
print("--- C) A1Z26 null mask + simple sub ---")
crib_set = set(CRIB_POSITIONS)

# The A1Z26 values mod 97 as null positions
candidate_nulls = []
for w, v in WORD_VALS:
    pos = v % 97
    if pos not in crib_set:
        candidate_nulls.append(pos)
candidate_nulls = list(set(candidate_nulls))

if len(candidate_nulls) >= 20:
    # Build best 24-position null mask from these candidates
    # Sort by specificity: prefer values that directly match known K4 structural numbers
    priority = [63, 74, 79, 65, 75, 67]  # DEGREES, POINT, SECONDS, SEVEN, NORTH, WEST
    null_mask = set(p for p in priority if p not in crib_set)
    for p in candidate_nulls:
        if len(null_mask) == 24:
            break
        null_mask.add(p)

    if len(null_mask) == 24:
        ct73 = "".join(c for i, c in enumerate(CT) if i not in null_mask)
        print(f"  A1Z26 null mask ({len(null_mask)} positions): {sorted(null_mask)}")
        print(f"  73-char CT: {ct73}")

        # Build shift map for crib scoring
        pos73 = 0
        orig_to_73 = {}
        for i in range(97):
            if i not in null_mask:
                orig_to_73[i] = pos73
                pos73 += 1

        def crib_score_73(pt73):
            sc = 0
            for orig_pos, ch in CRIB_DICT.items():
                if orig_pos not in null_mask and orig_pos in orig_to_73:
                    new_pos = orig_to_73[orig_pos]
                    if new_pos < len(pt73) and pt73[new_pos] == ch:
                        sc += 1
            return sc

        for period in [1, 3, 4, 5, 6, 7, 11, 13]:
            for kname, key in key_seqs.items():
                if not key:
                    continue
                key_p = key[:period] if len(key) >= period else (key * (period // len(key) + 1))[:period]
                for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                    pt73 = fn(ct73, key_p)
                    sc = crib_score_73(pt73)
                    results.append((sc, f"C_{cipher}_p{period}_{kname}_nullA1Z26", pt73))

# === D) Affine map y=ax+b (mod 97) using A1Z26 values ===
print("--- D) Affine transposition y=ax+b (mod 97) with A1Z26 params ---")
from math import gcd

# Candidate (a,b) pairs derived from A1Z26 values
a_candidates = [v % 97 for v in [63, 74, 79, 65, 75, 67, 24, 11, 13, 27, 21]]
b_candidates = [v % 97 for v in [21, 63, 74, 79, 24, 0, 11, 13]]

affine_results = []
for a in a_candidates:
    if a == 0 or gcd(a, 97) != 1:
        continue
    for b in b_candidates:
        # Permutation: position i in PT → CT position (a*i + b) mod 97
        perm = [(a * i + b) % 97 for i in range(97)]
        transposed = "".join(CT[perm[i]] for i in range(97))

        for period in range(1, 14):
            for kname, key in [("deg_pt_sec", [63 % 26, 74 % 26, 79 % 26]),
                                 ("allwords", vals_mod26)]:
                for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                    pt = fn(transposed, key[:period])
                    sc = crib_score(pt)
                    affine_results.append((sc, f"D_affine_a={a}_b={b}_{cipher}_p={period}_{kname}", pt))

results.extend(affine_results)

# === E) Pure A1Z26 position extraction → keyword ===
print("--- E) A1Z26 positions → keyword extraction ---")
# Extract CT letters at the 5 HIGHLIGHTED positions as potential keyword
key_word_chars = [CT[DEGREES_POS], CT[POINT_POS], CT[SECONDS_POS], CT[SEVEN_POS], CT[75], CT[67]]
print(f"  CT chars at highlighted positions: {''.join(key_word_chars)}")
print(f"  Positions: DEGREES={DEGREES_POS}→{CT[DEGREES_POS]}, POINT={POINT_POS}→{CT[POINT_POS]}, SECONDS={SECONDS_POS}→{CT[SECONDS_POS]}, SEVEN={SEVEN_POS}→{CT[SEVEN_POS]}, NORTH=75→{CT[75]}, WEST=67→{CT[67]}")

for length in range(3, 7):
    key_letters = key_word_chars[:length]
    key_nums = [ALPH_IDX[c] for c in key_letters]
    for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
        pt = fn(CT, key_nums)
        sc = crib_score(pt)
        results.append((sc, f"E_{cipher}_len{length}_{''.join(key_letters)}", pt))

# === Summary ===
results.sort(key=lambda x: -x[0])
above_noise = [(s, l, p) for s, l, p in results if s > 6]
print(f"\nTotal configs tested: {len(results)}")
print(f"Above noise (>6): {len(above_noise)}")

if above_noise:
    print("\nALL ABOVE-NOISE RESULTS:")
    for sc, label, pt in above_noise[:20]:
        matches = [(pos, CRIB_DICT[pos]) for pos in sorted(CRIB_POSITIONS)
                   if pos < len(pt) and pt[pos] == CRIB_DICT[pos]]
        print(f"  Score {sc:2d}/24: {label}")
        print(f"    PT: {pt[:60]}")
        print(f"    Matches: {matches}")
        print()

print("\nTop 10:")
for sc, label, pt in results[:10]:
    print(f"  {sc:2d}/24: {label} | {pt[:50]}")
print("\nDONE")
