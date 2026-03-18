#!/usr/bin/env python3
"""
Cipher: Beaufort/Vigenere (coordinate-derived key generation)
Family: analysis
Status: active
Keyspace: ~500K configurations across 8 investigations
Last run: 2026-03-16
Best score: TBD
"""
"""K2 COORDINATE KEY GENERATION: 8 investigations into how K2 coordinates
generate the K4 cipher key.

Premise: The AP {G(6), K(10), O(14)} with step=4 covers 12/24 known keystream
values under Model B Beaufort. The step 4 connects to 6.5 via 26/4=6.5.
Sanborn FALSIFIED the latitude from 8.1" to 6.5" -- deliberate choice.
"What's the point?" = the decimal point in 6.5.

Known Beaufort keystream (24 positions):
  Pos: 21 22 23 24 25 26 27 28 29 30 31 32 33  63 64 65 66 67 68 69 70 71 72 73
  Key:  9 11  9 14  3  4  6 10 20 10 10 10 11  14  2  6  6  1  6 14 10 19 17 20

Investigations:
  1. AP base key + correction analysis
  2. Key = (4 * f(i) + g(i)) mod 26 composite models
  3. Coordinate numbers as key generation seed
  4. 6.5 as the fundamental constant (floor/round of 6.5*i)
  5. K2 coordinate numbers as Fibonacci/recurrence seed
  6. "POINT" as multiplication (period-6 x period-5 interleave)
  7. Period-13 AP with coordinate-derived corrections
  8. Exhaustive multiplicative key search (non-coprime a values)
"""

import json, sys, os, time, math, itertools
from collections import Counter, defaultdict

# ── Constants ──────────────────────────────────────────────────────────
CT97 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
N2L = {i: c for i, c in enumerate(AZ)}
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_I2N = {c: i for i, c in enumerate(KA)}

ENE_START, ENE_TEXT = 21, "EASTNORTHEAST"
BCL_START, BCL_TEXT = 63, "BERLINCLOCK"

CT_NUMS = [I2N[c] for c in CT97]

# Build known keystream (Beaufort: K = (CT + PT) mod 26)
CRIB_POSITIONS = []
BEAU_KEY = {}  # pos -> key value
PT_AT = {}
for i, ch in enumerate(ENE_TEXT):
    pos = ENE_START + i
    CRIB_POSITIONS.append(pos)
    PT_AT[pos] = I2N[ch]
    BEAU_KEY[pos] = (CT_NUMS[pos] + I2N[ch]) % 26
for i, ch in enumerate(BCL_TEXT):
    pos = BCL_START + i
    CRIB_POSITIONS.append(pos)
    PT_AT[pos] = I2N[ch]
    BEAU_KEY[pos] = (CT_NUMS[pos] + I2N[ch]) % 26

# Also compute Vigenere key for comparison
VIG_KEY = {}
for pos in CRIB_POSITIONS:
    VIG_KEY[pos] = (CT_NUMS[pos] - PT_AT[pos]) % 26

AP_VALUES = {6, 10, 14}  # The AP with step 4

# Thematic keywords and their numeric representations
KEYWORDS = {
    'KRYPTOS': [I2N[c] for c in 'KRYPTOS'],
    'DEFECTOR': [I2N[c] for c in 'DEFECTOR'],
    'ABSCISSA': [I2N[c] for c in 'ABSCISSA'],
    'PALIMPSEST': [I2N[c] for c in 'PALIMPSEST'],
    'KOMPASS': [I2N[c] for c in 'KOMPASS'],
    'COLOPHON': [I2N[c] for c in 'COLOPHON'],
    'PARALLAX': [I2N[c] for c in 'PARALLAX'],
    'BERLINCLOCK': [I2N[c] for c in 'BERLINCLOCK'],
    'ENIGMA': [I2N[c] for c in 'ENIGMA'],
    'SEVEN': [I2N[c] for c in 'SEVEN'],
}
KEYWORDS_KA = {
    name: [KA_I2N[c] for c in name] for name in KEYWORDS
}

def score_key_func(key_func, positions=None):
    """Score a key generation function against known Beaufort keystream.
    Returns (matches, total, details)."""
    if positions is None:
        positions = CRIB_POSITIONS
    matches = 0
    total = len(positions)
    details = []
    for pos in positions:
        predicted = key_func(pos) % 26
        actual = BEAU_KEY[pos]
        match = (predicted == actual)
        if match:
            matches += 1
        details.append((pos, predicted, actual, match))
    return matches, total, details

def score_key_func_vig(key_func, positions=None):
    """Score against Vigenere keystream."""
    if positions is None:
        positions = CRIB_POSITIONS
    matches = 0
    for pos in positions:
        predicted = key_func(pos) % 26
        actual = VIG_KEY[pos]
        if predicted == actual:
            matches += 1
    return matches

def decrypt_beaufort(key_97):
    """Decrypt CT97 using Beaufort with a 97-element key list."""
    pt = []
    for i in range(97):
        pt_val = (key_97[i] - CT_NUMS[i]) % 26
        pt.append(N2L[pt_val])
    return ''.join(pt)


results = {
    'experiment': 'K2-COORDINATE-KEY-GENERATION',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    'model': 'Model B Beaufort on raw CT97',
    'known_keystream': {pos: BEAU_KEY[pos] for pos in CRIB_POSITIONS},
}

# ════════════════════════════════════════════════════════════════════════
# INVESTIGATION 1: AP base key + correction analysis
# ════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("INVESTIGATION 1: AP base key + correction analysis")
print("=" * 72)

inv1_results = {}
best_start = -1
best_matches = 0

for start in range(26):
    matches = 0
    corrections = []
    for pos in CRIB_POSITIONS:
        ap_key = (start + 4 * pos) % 26
        actual = BEAU_KEY[pos]
        if ap_key == actual:
            matches += 1
            corrections.append((pos, 0, True))
        else:
            correction = (actual - ap_key) % 26
            corrections.append((pos, correction, False))
    if matches > best_matches:
        best_matches = matches
        best_start = start
        best_corrections = corrections

print(f"Best start value: {best_start} ({N2L[best_start]})")
print(f"Matches: {best_matches}/24")
print()

# Also try AP with period 13: key[i] = (start + 4*(i mod 13)) mod 26
best_p13_start = -1
best_p13_matches = 0

for start in range(26):
    matches = 0
    for pos in CRIB_POSITIONS:
        ap_key = (start + 4 * (pos % 13)) % 26
        actual = BEAU_KEY[pos]
        if ap_key == actual:
            matches += 1
    if matches > best_p13_matches:
        best_p13_matches = matches
        best_p13_start = start

print(f"Period-13 AP: best start = {best_p13_start} ({N2L[best_p13_start]})")
print(f"Period-13 matches: {best_p13_matches}/24")

# Detailed correction analysis for best start
print(f"\nDetailed corrections for start={best_start}:")
non_matching = [(pos, corr, m) for pos, corr, m in best_corrections if not m]
correction_values = [corr for _, corr, _ in non_matching]
print(f"Non-matching positions: {len(non_matching)}")
print(f"Correction values: {correction_values}")
print(f"Correction value counts: {Counter(correction_values)}")
print(f"Correction distinct: {len(set(correction_values))}")

# Check if corrections relate to coordinate numbers
coord_nums = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
print(f"\nCoordinate digits: {coord_nums}")
# Check cycling match
for offset in range(len(coord_nums)):
    match_count = 0
    for idx, (pos, corr, _) in enumerate(non_matching):
        cycle_val = coord_nums[(idx + offset) % len(coord_nums)]
        if corr == cycle_val:
            match_count += 1
    if match_count >= 3:
        print(f"  Coord offset {offset}: {match_count}/{len(non_matching)} correction matches")

inv1_results = {
    'best_start': best_start,
    'best_start_letter': N2L[best_start],
    'matches': best_matches,
    'period_13_best_start': best_p13_start,
    'period_13_matches': best_p13_matches,
    'non_matching_corrections': correction_values,
    'correction_distinct': len(set(correction_values)),
}
results['investigation_1'] = inv1_results
print()

# ════════════════════════════════════════════════════════════════════════
# INVESTIGATION 2: Key = (4 * f(i) + g(i)) mod 26
# ════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("INVESTIGATION 2: Key = (4 * f(i) + g(i)) mod 26")
print("=" * 72)

inv2_results = {'best_score': 0, 'best_configs': []}
tested = 0

# f(i) functions
def make_f_funcs():
    funcs = []
    funcs.append(('i', lambda i: i))
    funcs.append(('i_mod_13', lambda i: i % 13))
    funcs.append(('i_mod_7', lambda i: i % 7))
    funcs.append(('i_mod_4', lambda i: i % 4))
    # grid position (row/col in 14x7 grid)
    funcs.append(('grid14x7_row', lambda i: i // 7))
    funcs.append(('grid14x7_col', lambda i: i % 7))
    # KRYPTOS[i mod 7]
    kryptos_vals = [I2N[c] for c in 'KRYPTOS']
    funcs.append(('KRYPTOS[i%7]', lambda i, kv=kryptos_vals: kv[i % 7]))
    # SEVEN[i mod 5]
    seven_vals = [I2N[c] for c in 'SEVEN']
    funcs.append(('SEVEN[i%5]', lambda i, sv=seven_vals: sv[i % 5]))
    # CT[i]
    funcs.append(('CT[i]', lambda i: CT_NUMS[i]))
    return funcs

# g(i) functions
def make_g_funcs():
    funcs = []
    for offset in range(26):
        funcs.append((f'const({offset})', lambda i, o=offset: o))
    kryptos_vals = [I2N[c] for c in 'KRYPTOS']
    funcs.append(('KRYPTOS[i%7]', lambda i, kv=kryptos_vals: kv[i % 7]))
    seven_vals = [I2N[c] for c in 'SEVEN']
    funcs.append(('SEVEN[i%5]', lambda i, sv=seven_vals: sv[i % 5]))
    # PT-autokey: g(i) = PT[i] (only testable at crib positions)
    funcs.append(('PT[i]', 'PT_AUTOKEY'))
    funcs.append(('CT[i]', lambda i: CT_NUMS[i]))
    return funcs

f_funcs = make_f_funcs()
g_funcs = make_g_funcs()

for f_name, f_func in f_funcs:
    for g_name, g_func in g_funcs:
        tested += 1
        # Handle PT-autokey specially
        if g_func == 'PT_AUTOKEY':
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (4 * f_func(pos) + PT_AT[pos]) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1
        else:
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (4 * f_func(pos) + g_func(pos)) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1

        if matches >= 8:
            config = f"f={f_name}, g={g_name}"
            inv2_results['best_configs'].append((matches, config))
            if matches > inv2_results['best_score']:
                inv2_results['best_score'] = matches
                print(f"  NEW BEST: {matches}/24 -- {config}")

# Also try: key[i] = (a * f(i) + g(i)) mod 26 for a in {2,3,4,5,6,13}
for a in [2, 3, 4, 5, 6, 13]:
    for f_name, f_func in f_funcs:
        for g_name, g_func in g_funcs:
            if g_func == 'PT_AUTOKEY':
                continue
            tested += 1
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (a * f_func(pos) + g_func(pos)) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 8:
                config = f"a={a}, f={f_name}, g={g_name}"
                inv2_results['best_configs'].append((matches, config))
                if matches > inv2_results['best_score']:
                    inv2_results['best_score'] = matches
                    print(f"  NEW BEST: {matches}/24 -- {config}")

inv2_results['tested'] = tested
inv2_results['best_configs'].sort(key=lambda x: -x[0])
inv2_results['best_configs'] = inv2_results['best_configs'][:20]
print(f"Tested {tested} configs. Best: {inv2_results['best_score']}/24")
results['investigation_2'] = inv2_results
print()

# ════════════════════════════════════════════════════════════════════════
# INVESTIGATION 3: Coordinate numbers as key generation seed
# ════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("INVESTIGATION 3: Coordinate numbers as key generation seed")
print("=" * 72)

inv3_results = {'tests': [], 'best_score': 0}

# 3a: Coordinate digits cycling as Gronsfeld key
coord_digits_lat = [3, 8, 5, 7, 6, 5]  # 38°57'6.5"
coord_digits_lon = [7, 7, 8, 4, 4]     # 77°8'44"
coord_digits_all = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]

digit_seqs = [
    ('lat_385765', coord_digits_lat),
    ('lon_77844', coord_digits_lon),
    ('all_38576577844', coord_digits_all),
    ('lat_rev', list(reversed(coord_digits_lat))),
    ('lon_rev', list(reversed(coord_digits_lon))),
    ('all_rev', list(reversed(coord_digits_all))),
    # Treat 6.5 as 65
    ('lat_385765_as_65', [3, 8, 5, 7, 65 % 26]),
    # Treat 6.5 as 6,13 (since 0.5*26=13)
    ('lat_6half_as_613', [3, 8, 5, 7, 6, 13]),
]

for seq_name, seq in digit_seqs:
    L = len(seq)
    # Direct cycling
    matches = 0
    for pos in CRIB_POSITIONS:
        if seq[pos % L] == BEAU_KEY[pos]:
            matches += 1
    inv3_results['tests'].append((f'gronsfeld_{seq_name}', matches))
    if matches > inv3_results['best_score']:
        inv3_results['best_score'] = matches

    # Multiply by 4
    seq4 = [(v * 4) % 26 for v in seq]
    matches = 0
    for pos in CRIB_POSITIONS:
        if seq4[pos % L] == BEAU_KEY[pos]:
            matches += 1
    inv3_results['tests'].append((f'x4_{seq_name}', matches))
    if matches > inv3_results['best_score']:
        inv3_results['best_score'] = matches

    # Multiply by various factors + various offsets
    for mult in [1, 2, 3, 4, 5, 6, 13]:
        for offset in range(26):
            seqm = [(v * mult + offset) % 26 for v in seq]
            matches = 0
            for pos in CRIB_POSITIONS:
                if seqm[pos % L] == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 8:
                config = f'mult{mult}_off{offset}_{seq_name}'
                inv3_results['tests'].append((config, matches))
                if matches > inv3_results['best_score']:
                    inv3_results['best_score'] = matches
                    print(f"  NEW BEST: {matches}/24 -- {config}")

# 3b: key[i] = (4*digit_sequence[i mod L] + offset) mod 26
for seq_name, seq in digit_seqs:
    L = len(seq)
    for offset in range(26):
        matches = 0
        for pos in CRIB_POSITIONS:
            predicted = (4 * seq[pos % L] + offset) % 26
            if predicted == BEAU_KEY[pos]:
                matches += 1
        if matches >= 6:
            config = f'4d+{offset}_{seq_name}'
            inv3_results['tests'].append((config, matches))
            if matches > inv3_results['best_score']:
                inv3_results['best_score'] = matches
                print(f"  NEW BEST: {matches}/24 -- {config}")

# 3c: Decimal representation of coordinates as digit key
# 38.950138889... (latitude in degrees)
# 77.134444444... (longitude in degrees)
lat_decimal = 38 + 57/60 + 6.5/3600  # = 38.95180556
lon_decimal = 77 + 8/60 + 44/3600    # = 77.14555556

# Extract digits after decimal point
import decimal
lat_digits = []
lat_str = f"{lat_decimal:.20f}"
for ch in lat_str.split('.')[1][:20]:
    lat_digits.append(int(ch))
lon_digits = []
lon_str = f"{lon_decimal:.20f}"
for ch in lon_str.split('.')[1][:20]:
    lon_digits.append(int(ch))

# Interleaved digits
interleaved = []
for j in range(20):
    if j < len(lat_digits):
        interleaved.append(lat_digits[j])
    if j < len(lon_digits):
        interleaved.append(lon_digits[j])

decimal_seqs = [
    ('lat_decimal_digits', lat_digits[:15]),
    ('lon_decimal_digits', lon_digits[:15]),
    ('interleaved_decimal', interleaved[:20]),
]

for seq_name, seq in decimal_seqs:
    L = len(seq)
    # Direct as Gronsfeld
    matches = 0
    for pos in CRIB_POSITIONS:
        if seq[pos % L] == BEAU_KEY[pos]:
            matches += 1
    inv3_results['tests'].append((f'decimal_{seq_name}', matches))

    # Scaled
    for mult in [1, 2, 3, 4, 5, 6, 13]:
        for offset in range(26):
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (mult * seq[pos % L] + offset) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 7:
                config = f'decimal_m{mult}_o{offset}_{seq_name}'
                inv3_results['tests'].append((config, matches))
                if matches > inv3_results['best_score']:
                    inv3_results['best_score'] = matches
                    print(f"  NEW BEST: {matches}/24 -- {config}")

# 3d: Use angles in other representations
# Radians
lat_rad = math.radians(lat_decimal)
lon_rad = math.radians(lon_decimal)
# Digits of radians
for name, val in [('lat_rad', lat_rad), ('lon_rad', lon_rad)]:
    digits = []
    s = f"{val:.20f}"
    for ch in s.replace('.', ''):
        if ch.isdigit():
            digits.append(int(ch))
    digits = digits[:20]
    for mult in [1, 4]:
        for offset in range(26):
            L = len(digits)
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (mult * digits[pos % L] + offset) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 7:
                config = f'{name}_m{mult}_o{offset}'
                inv3_results['tests'].append((config, matches))
                if matches > inv3_results['best_score']:
                    inv3_results['best_score'] = matches
                    print(f"  NEW BEST: {matches}/24 -- {config}")

inv3_results['tests'].sort(key=lambda x: -x[1])
inv3_results['tests'] = inv3_results['tests'][:30]
print(f"Investigation 3 best: {inv3_results['best_score']}/24")
results['investigation_3'] = inv3_results
print()

# ════════════════════════════════════════════════════════════════════════
# INVESTIGATION 4: 6.5 as the fundamental constant
# ════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("INVESTIGATION 4: 6.5 as the fundamental constant")
print("=" * 72)

inv4_results = {'tests': [], 'best_score': 0}

# 4a: key[i] = floor(6.5 * i) mod 26
# Period: A(0), G(6), N(13), T(19), A(0), G(6)... period 4
print("floor(6.5*i) mod 26 pattern: ", end="")
for i in range(8):
    v = int(6.5 * i) % 26
    print(f"{N2L[v]}({v})", end=" ")
print()

# With offsets
for func_name, func in [
    ('floor_6.5i', lambda i: int(6.5 * i)),
    ('round_6.5i', lambda i: round(6.5 * i)),
    ('ceil_6.5i', lambda i: math.ceil(6.5 * i)),
    ('floor_13i/2', lambda i: (13 * i) // 2),
]:
    for offset_b in range(26):
        for offset_c in range(97):
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (func(pos + offset_c) + offset_b) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 8:
                config = f'{func_name}_b{offset_b}_c{offset_c}'
                inv4_results['tests'].append((config, matches))
                if matches > inv4_results['best_score']:
                    inv4_results['best_score'] = matches
                    print(f"  NEW BEST: {matches}/24 -- {config}")

# 4b: key[i] = floor(6.5 * (i + c)) mod 26  for c in 0-96
# Already covered above

# 4c: key[i] = floor(k * i) mod 26 for k in {6.5, 3.25, 13.0, 4.0, 4.333..., 2.0}
for k_name, k_val in [
    ('6.5', 6.5), ('3.25', 3.25), ('13.0', 13.0), ('4.0', 4.0),
    ('4.333', 13/3), ('2.0', 2.0), ('8.666', 26/3), ('5.2', 26/5),
    ('26/7', 26/7), ('26/11', 26/11), ('26/13', 26/13),
]:
    for offset_b in range(26):
        for offset_c in range(26):  # Smaller range for these
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (int(k_val * (pos + offset_c)) + offset_b) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 8:
                config = f'floor({k_name}*(i+{offset_c}))+{offset_b}'
                inv4_results['tests'].append((config, matches))
                if matches > inv4_results['best_score']:
                    inv4_results['best_score'] = matches
                    print(f"  NEW BEST: {matches}/24 -- {config}")

inv4_results['tests'].sort(key=lambda x: -x[1])
inv4_results['tests'] = inv4_results['tests'][:30]
print(f"Investigation 4 best: {inv4_results['best_score']}/24")
results['investigation_4'] = inv4_results
print()

# ════════════════════════════════════════════════════════════════════════
# INVESTIGATION 5: K2 coordinate numbers as Fibonacci/recurrence seed
# ════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("INVESTIGATION 5: Fibonacci/recurrence with coordinate seeds")
print("=" * 72)

inv5_results = {'tests': [], 'best_score': 0}

# Seeds to try
seeds = [
    ('lat_385765', [3, 8, 5, 7, 6, 5]),
    ('lon_77844', [7, 7, 8, 4, 4]),
    ('all_38576577844', [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]),
    ('lat_6half', [3, 8, 5, 7, 6, 13]),  # 6.5 -> 6, 13
    ('K2_numbers', [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]),
    ('K2_lat_full', [38, 57, 6, 5]),  # As DMS components
    ('K2_lon_full', [77, 8, 44]),
    ('K2_both_full', [38, 57, 6, 5, 77, 8, 44]),
]

# Recurrence types
for seed_name, seed in seeds:
    L = len(seed)
    for mod_val in [10, 13, 26]:
        # Fibonacci-like: k[i] = (k[i-L] + k[i-L+1]) mod mod_val
        seq = list(seed)
        for i in range(L, 97):
            seq.append((seq[i - L] + seq[i - L + 1]) % mod_val)
        matches = 0
        for pos in CRIB_POSITIONS:
            if seq[pos] % 26 == BEAU_KEY[pos]:
                matches += 1
        if matches >= 5:
            config = f'fib_{seed_name}_mod{mod_val}'
            inv5_results['tests'].append((config, matches))
        if matches > inv5_results['best_score']:
            inv5_results['best_score'] = matches
            if matches >= 6:
                print(f"  NEW BEST: {matches}/24 -- fib_{seed_name}_mod{mod_val}")

        # Additive: k[i] = (k[i-1] + k[i-L]) mod mod_val
        seq2 = list(seed)
        for i in range(L, 97):
            seq2.append((seq2[i - 1] + seq2[i - L]) % mod_val)
        matches2 = 0
        for pos in CRIB_POSITIONS:
            if seq2[pos] % 26 == BEAU_KEY[pos]:
                matches2 += 1
        if matches2 >= 5:
            config = f'additive_{seed_name}_mod{mod_val}'
            inv5_results['tests'].append((config, matches2))
        if matches2 > inv5_results['best_score']:
            inv5_results['best_score'] = matches2
            if matches2 >= 6:
                print(f"  NEW BEST: {matches2}/24 -- additive_{seed_name}_mod{mod_val}")

        # Chain addition (Gromark-like): k[i] = (k[i-1] + k[i-2]) mod mod_val
        if L >= 2:
            seq3 = [s % mod_val for s in seed]
            for i in range(L, 97):
                seq3.append((seq3[i - 1] + seq3[i - 2]) % mod_val)
            matches3 = 0
            for pos in CRIB_POSITIONS:
                if seq3[pos] % 26 == BEAU_KEY[pos]:
                    matches3 += 1
            if matches3 >= 5:
                config = f'chain2_{seed_name}_mod{mod_val}'
                inv5_results['tests'].append((config, matches3))
            if matches3 > inv5_results['best_score']:
                inv5_results['best_score'] = matches3
                if matches3 >= 6:
                    print(f"  NEW BEST: {matches3}/24 -- chain2_{seed_name}_mod{mod_val}")

# Extended: try ALL 2-digit primers from coordinate numbers as Fibonacci seed
coord_source = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
for i in range(len(coord_source)):
    for j in range(len(coord_source)):
        seed_2 = [coord_source[i], coord_source[j]]
        for mod_val in [10, 26]:
            seq = list(seed_2)
            for k in range(2, 97):
                seq.append((seq[k-1] + seq[k-2]) % mod_val)
            matches = 0
            for pos in CRIB_POSITIONS:
                if seq[pos] % 26 == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 6:
                inv5_results['tests'].append((f'fib2_seed({coord_source[i]},{coord_source[j]})_mod{mod_val}', matches))
                if matches > inv5_results['best_score']:
                    inv5_results['best_score'] = matches
                    print(f"  NEW BEST: {matches}/24 -- fib2_seed({coord_source[i]},{coord_source[j]})_mod{mod_val}")

inv5_results['tests'].sort(key=lambda x: -x[1])
inv5_results['tests'] = inv5_results['tests'][:30]
print(f"Investigation 5 best: {inv5_results['best_score']}/24")
results['investigation_5'] = inv5_results
print()

# ════════════════════════════════════════════════════════════════════════
# INVESTIGATION 6: The "POINT" as multiplication
# ════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("INVESTIGATION 6: 'POINT' as multiplication / interleave")
print("=" * 72)

inv6_results = {'tests': [], 'best_score': 0}

# 6a: Key[i] = (6 * KRYPTOS[i%7] + 5 * SEVEN[i%5]) mod 26
# And all variations
kw_pairs = [
    ('KRYPTOS', 7, KEYWORDS['KRYPTOS']),
    ('DEFECTOR', 8, KEYWORDS['DEFECTOR']),
    ('ABSCISSA', 8, KEYWORDS['ABSCISSA']),
    ('SEVEN', 5, KEYWORDS['SEVEN']),
    ('ENIGMA', 6, KEYWORDS['ENIGMA']),
    ('BERLINCLOCK', 11, KEYWORDS['BERLINCLOCK']),
    ('KOMPASS', 7, KEYWORDS['KOMPASS']),
]

for (kw1_name, kw1_len, kw1_vals), (kw2_name, kw2_len, kw2_vals) in itertools.combinations(kw_pairs, 2):
    for a in [5, 6, 13]:
        for b in [5, 6, 13]:
            for sign in [1, -1]:
                matches = 0
                for pos in CRIB_POSITIONS:
                    v1 = kw1_vals[pos % kw1_len]
                    v2 = kw2_vals[pos % kw2_len]
                    predicted = (a * v1 + sign * b * v2) % 26
                    if predicted == BEAU_KEY[pos]:
                        matches += 1
                if matches >= 6:
                    s = '+' if sign == 1 else '-'
                    config = f'{a}*{kw1_name}[%{kw1_len}]{s}{b}*{kw2_name}[%{kw2_len}]'
                    inv6_results['tests'].append((config, matches))
                    if matches > inv6_results['best_score']:
                        inv6_results['best_score'] = matches
                        print(f"  NEW BEST: {matches}/24 -- {config}")

# 6b: Interleave period-6 and period-5 components
# Key[i] = (period6[i mod 6] + period5[i mod 5]) mod 26
# Exhaustive over period-6 components that place {6,10,14} in the right spots
# Just try all offset combinations
for a6 in range(26):
    for a5 in range(26):
        matches = 0
        for pos in CRIB_POSITIONS:
            predicted = ((a6 * (pos % 6)) + (a5 * (pos % 5))) % 26
            if predicted == BEAU_KEY[pos]:
                matches += 1
        if matches >= 8:
            config = f'linear6={a6}_linear5={a5}'
            inv6_results['tests'].append((config, matches))
            if matches > inv6_results['best_score']:
                inv6_results['best_score'] = matches
                print(f"  NEW BEST: {matches}/24 -- {config}")

# 6c: Key[i] = (6 * f1(i) + 5 * f2(i) + offset) mod 26
# where f1 and f2 cycle with different periods
for p1 in [5, 6, 7, 11, 13]:
    for p2 in [5, 6, 7, 11, 13]:
        if p1 == p2:
            continue
        for offset in range(26):
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (6 * (pos % p1) + 5 * (pos % p2) + offset) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 7:
                config = f'6*(i%{p1})+5*(i%{p2})+{offset}'
                inv6_results['tests'].append((config, matches))
                if matches > inv6_results['best_score']:
                    inv6_results['best_score'] = matches
                    print(f"  NEW BEST: {matches}/24 -- {config}")

inv6_results['tests'].sort(key=lambda x: -x[1])
inv6_results['tests'] = inv6_results['tests'][:30]
print(f"Investigation 6 best: {inv6_results['best_score']}/24")
results['investigation_6'] = inv6_results
print()

# ════════════════════════════════════════════════════════════════════════
# INVESTIGATION 7: Period-13 AP with coordinate-derived corrections
# ════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("INVESTIGATION 7: Period-13 AP + corrections")
print("=" * 72)

inv7_results = {'tests': [], 'best_score': 0, 'correction_analysis': {}}

# For each start value, compute AP key at crib positions with period 13
for start in range(26):
    matching_positions = []
    non_matching = []
    corrections = {}

    for pos in CRIB_POSITIONS:
        ap_key = (start + 4 * (pos % 13)) % 26
        actual = BEAU_KEY[pos]
        if ap_key == actual:
            matching_positions.append(pos)
        else:
            correction = (actual - ap_key) % 26
            non_matching.append(pos)
            corrections[pos] = correction

    n_match = len(matching_positions)

    if n_match >= 4:  # Worth analyzing
        corr_vals = list(corrections.values())
        corr_counter = Counter(corr_vals)

        # Check if corrections are from coordinate numbers
        coord_set = set(coord_digits_all)
        coord_matches = sum(1 for v in corr_vals if v in coord_set)

        # Check if corrections have small range
        if corr_vals:
            corr_range = max(corr_vals) - min(corr_vals) if len(set(corr_vals)) > 1 else 0
            corr_distinct = len(set(corr_vals))
        else:
            corr_range = 0
            corr_distinct = 0

        inv7_results['tests'].append({
            'start': start,
            'start_letter': N2L[start],
            'ap_matches': n_match,
            'corrections': corrections,
            'correction_distinct': corr_distinct,
            'correction_range': corr_range,
            'coord_match_count': coord_matches,
        })

        if n_match > inv7_results['best_score']:
            inv7_results['best_score'] = n_match
            print(f"  Start={start}({N2L[start]}): {n_match}/24 AP matches")
            print(f"    Corrections: {corr_counter.most_common(5)}")
            print(f"    Distinct: {corr_distinct}, Range: {corr_range}")

# For the best start, do deep correction analysis
inv7_results['tests'].sort(key=lambda x: -x['ap_matches'])
if inv7_results['tests']:
    best = inv7_results['tests'][0]
    corrections_dict = best['corrections']
    print(f"\nDeep analysis for start={best['start']} ({best['start_letter']}):")

    # Check if corrections follow a keyword pattern
    non_match_positions = sorted(corrections_dict.keys())
    corr_seq = [corrections_dict[p] for p in non_match_positions]
    print(f"  Non-matching positions: {non_match_positions}")
    print(f"  Correction sequence: {corr_seq}")
    print(f"  As letters: {''.join(N2L[c] for c in corr_seq)}")

    # Check if correction = KRYPTOS[f(pos)] for some f
    for kw_name, kw_vals in KEYWORDS.items():
        L = len(kw_vals)
        matches = 0
        for pos in non_match_positions:
            if corrections_dict[pos] == kw_vals[pos % L]:
                matches += 1
        if matches >= 3:
            print(f"  Corr={kw_name}[pos%{L}]: {matches}/{len(non_match_positions)} match")

    # Check if correction = constant per residue class
    residue_corr = defaultdict(set)
    for pos in non_match_positions:
        r = pos % 13
        residue_corr[r].add(corrections_dict[pos])
    consistent_residues = sum(1 for r, vals in residue_corr.items() if len(vals) == 1)
    print(f"  Consistent residues mod 13: {consistent_residues}/{len(residue_corr)}")

print(f"Investigation 7 best: {inv7_results['best_score']}/24 AP matches")
results['investigation_7'] = inv7_results
print()

# ════════════════════════════════════════════════════════════════════════
# INVESTIGATION 8: Exhaustive multiplicative key search
# ════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("INVESTIGATION 8: Exhaustive multiplicative key search")
print("=" * 72)

inv8_results = {'tests': [], 'best_score': 0, 'tested': 0}

# key[i] = (a * (i + c) + b) mod 26 for all a (0-25), b (0-25), c (0-96)
# Focus on non-coprime a values that give sub-period structure
# a=4 gives period 13 (gcd(4,26)=2), same as the AP step
total = 0
for a in range(26):
    for b in range(26):
        for c in range(97):
            total += 1
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (a * (pos + c) + b) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 10:
                config = f'a={a},b={b},c={c}'
                inv8_results['tests'].append((config, matches))
                if matches > inv8_results['best_score']:
                    inv8_results['best_score'] = matches
                    print(f"  NEW BEST: {matches}/24 -- key=(({a}*(i+{c})+{b})%26")

inv8_results['tested'] = total
inv8_results['tests'].sort(key=lambda x: -x[1])
inv8_results['tests'] = inv8_results['tests'][:30]
print(f"Tested {total} configs. Best: {inv8_results['best_score']}/24")

# Also: key[i] = floor(a * (i + c) / d) mod 26 for rational multipliers a/d
print("\nRational multiplier search: key[i] = floor(a*(i+c)/d) mod 26")
for d in range(1, 14):
    for a in range(1, 26):
        if a % d == 0:
            continue  # Skip integer multipliers (already tested above)
        for b in range(26):
            for c in range(26):
                inv8_results['tested'] += 1
                matches = 0
                for pos in CRIB_POSITIONS:
                    predicted = ((a * (pos + c)) // d + b) % 26
                    if predicted == BEAU_KEY[pos]:
                        matches += 1
                if matches >= 10:
                    config = f'floor({a}*(i+{c})/{d})+{b}'
                    inv8_results['tests'].append((config, matches))
                    if matches > inv8_results['best_score']:
                        inv8_results['best_score'] = matches
                        print(f"  NEW BEST: {matches}/24 -- {config}")

inv8_results['tests'].sort(key=lambda x: -x[1])
inv8_results['tests'] = inv8_results['tests'][:30]
print(f"Total tested: {inv8_results['tested']}. Final best: {inv8_results['best_score']}/24")
results['investigation_8'] = inv8_results
print()

# ════════════════════════════════════════════════════════════════════════
# BONUS: Autokey with AP-derived primers
# ════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("BONUS: Autokey with AP-derived primers")
print("=" * 72)

# If the key starts with the AP (GKOS...) and then shifts to autokey
bonus_results = {'tests': [], 'best_score': 0}

# Generate all period-13 AP sequences starting from each value
for start in range(26):
    primer = [(start + 4 * j) % 26 for j in range(13)]

    # PT-autokey Beaufort: K[i] = primer[i] for i<L, K[i] = PT[i-L] for i>=L
    # PT[i] = (K[i] - CT[i]) mod 26
    # But we only know PT at crib positions, so test consistency
    # Actually for autokey we need to generate the WHOLE key, not just at cribs
    # Let's generate and check

    # Beaufort PT-autokey with 13-char primer
    key = list(primer)
    pt = []
    for i in range(97):
        if i < 13:
            k_val = key[i]
        else:
            k_val = pt[i - 13]  # PT autokey
        pt_val = (k_val - CT_NUMS[i]) % 26
        pt.append(pt_val)
        if i >= 13:
            key.append(pt_val)

    matches = 0
    for pos in CRIB_POSITIONS:
        if pt[pos] == PT_AT[pos]:
            matches += 1

    if matches >= 5:
        pt_str = ''.join(N2L[v] for v in pt)
        bonus_results['tests'].append((f'beau_pt_autokey_primer=AP({N2L[start]})', matches, pt_str))
        if matches > bonus_results['best_score']:
            bonus_results['best_score'] = matches
            if matches >= 8:
                print(f"  NEW BEST: {matches}/24 -- beau_pt_autokey_primer=AP({N2L[start]})")
                print(f"    PT: {pt_str}")

    # CT-autokey Beaufort with 13-char primer
    key_ct = list(primer)
    pt_ct = []
    for i in range(97):
        if i < 13:
            k_val = key_ct[i]
        else:
            k_val = CT_NUMS[i - 13]  # CT autokey
        pt_val = (k_val - CT_NUMS[i]) % 26
        pt_ct.append(pt_val)

    matches_ct = 0
    for pos in CRIB_POSITIONS:
        if pt_ct[pos] == PT_AT[pos]:
            matches_ct += 1

    if matches_ct >= 5:
        pt_str = ''.join(N2L[v] for v in pt_ct)
        bonus_results['tests'].append((f'beau_ct_autokey_primer=AP({N2L[start]})', matches_ct, pt_str))
        if matches_ct > bonus_results['best_score']:
            bonus_results['best_score'] = matches_ct
            if matches_ct >= 8:
                print(f"  NEW BEST: {matches_ct}/24 -- beau_ct_autokey_primer=AP({N2L[start]})")
                print(f"    PT: {pt_str}")

    # Vigenere PT-autokey
    key_v = list(primer)
    pt_v = []
    for i in range(97):
        if i < 13:
            k_val = key_v[i]
        else:
            k_val = pt_v[i - 13]
        pt_val = (CT_NUMS[i] - k_val) % 26
        pt_v.append(pt_val)

    matches_v = 0
    for pos in CRIB_POSITIONS:
        if pt_v[pos] == PT_AT[pos]:
            matches_v += 1

    if matches_v >= 5:
        pt_str = ''.join(N2L[v] for v in pt_v)
        bonus_results['tests'].append((f'vig_pt_autokey_primer=AP({N2L[start]})', matches_v, pt_str))
        if matches_v > bonus_results['best_score']:
            bonus_results['best_score'] = matches_v
            if matches_v >= 8:
                print(f"  NEW BEST: {matches_v}/24 -- vig_pt_autokey_primer=AP({N2L[start]})")
                print(f"    PT: {pt_str}")

# Also try: primer = coordinate digits mapped through AP
for seed_name, seed in seeds:
    primer_ap = [(4 * s) % 26 for s in seed]
    L = len(primer_ap)
    # Beaufort PT-autokey
    key = list(primer_ap)
    pt = []
    for i in range(97):
        if i < L:
            k_val = key[i]
        else:
            k_val = pt[i - L]
        pt_val = (k_val - CT_NUMS[i]) % 26
        pt.append(pt_val)

    matches = 0
    for pos in CRIB_POSITIONS:
        if pt[pos] == PT_AT[pos]:
            matches += 1
    if matches >= 5:
        pt_str = ''.join(N2L[v] for v in pt)
        bonus_results['tests'].append((f'beau_pt_autokey_4x{seed_name}_L{L}', matches, pt_str))
        if matches > bonus_results['best_score']:
            bonus_results['best_score'] = matches
            if matches >= 8:
                print(f"  NEW BEST: {matches}/24 -- beau_pt_autokey_4x{seed_name}")
                print(f"    PT: {pt_str}")

bonus_results['tests'].sort(key=lambda x: -x[1])
bonus_results['tests'] = [(t[0], t[1]) for t in bonus_results['tests'][:20]]
print(f"Bonus best: {bonus_results['best_score']}/24")
results['bonus_autokey'] = bonus_results

# ════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════
print()
print("=" * 72)
print("SUMMARY OF ALL INVESTIGATIONS")
print("=" * 72)

summaries = [
    ('Inv 1: AP base key + corrections', inv1_results.get('matches', 0)),
    ('Inv 2: (4*f(i)+g(i)) mod 26', inv2_results['best_score']),
    ('Inv 3: Coordinate digits as key', inv3_results['best_score']),
    ('Inv 4: 6.5 as fundamental constant', inv4_results['best_score']),
    ('Inv 5: Fibonacci/recurrence', inv5_results['best_score']),
    ('Inv 6: POINT multiplication', inv6_results['best_score']),
    ('Inv 7: Period-13 AP + corrections', inv7_results['best_score']),
    ('Inv 8: Exhaustive multiplicative', inv8_results['best_score']),
    ('Bonus: AP-derived autokey', bonus_results['best_score']),
]

for name, score in summaries:
    status = "NOISE" if score < 10 else ("INTERESTING" if score < 18 else "SIGNAL!")
    print(f"  {name}: {score}/24 [{status}]")

results['summary'] = {name: score for name, score in summaries}
results['global_best'] = max(score for _, score in summaries)
results['verdict'] = 'NOISE' if results['global_best'] < 10 else 'INTERESTING'
results['elapsed_seconds'] = time.time() - time.mktime(time.strptime(results['timestamp'], '%Y-%m-%dT%H:%M:%S'))

# Save results
outpath = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                       'results', 'k2_coordinate_key_generation.json')
with open(outpath, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nResults saved to {outpath}")
