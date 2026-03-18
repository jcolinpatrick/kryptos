#!/usr/bin/env python3
"""
Cipher: geometry/physical
Family: geometry
Status: active
Keyspace: ~50K configs across 10 hypothesis classes
Last run: 2026-03-15
Best score: TBD
"""
"""E-NDYAHR-PAIRED-FORCES-10: Test NDYAHR as three pairs of directional forces.

Hypothesis: The 6 displaced NDYAHR letters operate in THREE PAIRS:
  Pair 1 (N,D): REPULSION — N shifts left, D shifts right (horizontal axis)
  Pair 2 (Y,A): PARALLEL ATTRACTION — Both shift UP (vertical axis)
  Pair 3 (H,R): ASYMMETRIC — H shifts right, R shifts up+left

K4 NDYAHR positions (0-indexed):
  N: [29, 60, 63]    D: [55, 76, 83]
  Y: [64]            A: [49, 57, 90, 95]
  H: [9, 88]         R: [3, 23, 28, 96]

Tests:
  T1.  Pair distance analysis & significance
  T2.  Pair distances as cipher periods/widths
  T3.  Pair operations as transposition swaps
  T4.  Paired null marking (each letter marks directional neighbor as null)
  T5.  Comprehensive force-direction sweep (20 interpretations vs consensus)
  T6.  Pair operations as cipher type selectors (polyalphabetic regions)
  T7.  Between-pair regions as null zones
  T8.  NDYAHR pair distances as key vector
  T9.  Polybius coordinate system from pair positions
  T10. Combined best: any mask from T4/T5/T7 + DEFECTOR:AZ_beau autokey

Run: PYTHONPATH=src python3 -u scripts/geometry/e_ndyahr_paired_forces_10.py
"""

import sys
import os
import json
import time
import math
from collections import Counter, defaultdict
from itertools import product as iter_product, combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_DICT, N_CRIBS, CRIB_WORDS,
    NOISE_FLOOR, STORE_THRESHOLD, CRIB_POSITIONS,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

# Try to load quadgram scorer
try:
    with open(os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')) as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1.0

    def qg_score(text):
        if len(text) < 4:
            return -10.0
        total = 0.0
        for i in range(len(text) - 3):
            qg = text[i:i+4]
            total += QUADGRAMS.get(qg, QG_FLOOR)
        return total / len(text)
except Exception:
    def qg_score(text):
        return -10.0

# ══════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════

CT97 = CT
N = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63

KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_IDX = ALPH_IDX

CONSENSUS_17 = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})

# Known 15/24 masks (from prior experiments)
MASKS_24 = [
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95],
]

# NDYAHR positions in K4
NDYAHR_K4 = {
    'N': [], 'D': [], 'Y': [], 'A': [], 'H': [], 'R': []
}
for i, ch in enumerate(CT97):
    if ch in NDYAHR_K4:
        NDYAHR_K4[ch].append(i)

# Verify
print("K4 NDYAHR positions:")
for letter in 'NDYAHR':
    print(f"  {letter}: {NDYAHR_K4[letter]}")

# Pairs
PAIRS = [
    ('N', 'D', 'REPULSION'),
    ('Y', 'A', 'PARALLEL'),
    ('H', 'R', 'ASYMMETRIC'),
]

# Direction assignments (from physical sculpture)
# N: LEFT, D: RIGHT, Y: UP, A: UP, H: RIGHT, R: UP-LEFT
LETTER_DIR = {
    'N': ('LEFT',  (-1, 0)),    # (dx, dy) where +x=right, +y=down
    'D': ('RIGHT', (+1, 0)),
    'Y': ('UP',    (0, -1)),
    'A': ('UP',    (0, -1)),
    'H': ('RIGHT', (+1, 0)),
    'R': ('UP-LEFT', (-1, -1)),
}

# Grid layout for K4 (width 31)
GRID_WIDTH = 31
def pos_to_grid(p):
    """Convert K4 linear position to (row_offset, col) in 28x31 grid.
    K4 starts at row 24, col 27."""
    # Row 24 (partial): cols 27-30 = K4[0:4]
    # Row 25: cols 0-30 = K4[4:35]
    # Row 26: cols 0-30 = K4[35:66]
    # Row 27: cols 0-30 = K4[66:97]
    if p < 4:
        return (24, 27 + p)
    elif p < 35:
        return (25, p - 4)
    elif p < 66:
        return (26, p - 35)
    else:
        return (27, p - 66)

def grid_to_pos(row, col):
    """Convert grid (row, col) to K4 linear position, or None if outside K4."""
    if row == 24 and 27 <= col <= 30:
        return col - 27
    elif row == 25 and 0 <= col <= 30:
        return col + 4
    elif row == 26 and 0 <= col <= 30:
        return col + 35
    elif row == 27 and 0 <= col <= 30:
        return col + 66
    return None

# Decryption helpers
def beau_decrypt_char(ct_val, key_val):
    return (key_val - ct_val) % 26

def vig_decrypt_char(ct_val, key_val):
    return (ct_val - key_val) % 26

def autokey_decrypt(ct_text, keyword, variant='beau', alpha='AZ'):
    """Decrypt with PT-autokey."""
    idx = AZ_IDX if alpha == 'AZ' else KA_IDX
    alph = ALPH if alpha == 'AZ' else KA_STR
    kw_vals = [idx[c] for c in keyword]
    ct_vals = [idx[c] for c in ct_text]
    pt_vals = []
    key_stream = list(kw_vals)
    for i, cv in enumerate(ct_vals):
        kv = key_stream[i % len(key_stream)] if i < len(key_stream) else key_stream[i]
        if variant == 'beau':
            pv = (kv - cv) % 26
        elif variant == 'vig':
            pv = (cv - kv) % 26
        else:
            pv = (pv - cv) % 26  # varbeau
        pt_vals.append(pv)
        if i >= len(key_stream) - 1:
            key_stream.append(pv)
    return ''.join(alph[v] for v in pt_vals)

def score_crib_match(pt_text):
    """Score how many crib positions match."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_text) and pt_text[pos] == ch:
            matches += 1
    return matches

def extract_73(mask_set):
    """Extract 73-char CT from 97-char CT by removing mask positions."""
    return ''.join(CT97[i] for i in range(N) if i not in mask_set)

results = {}
t0 = time.time()

# ══════════════════════════════════════════════════════════════════════════
# T1: PAIR DISTANCE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*72)
print("T1: PAIR DISTANCE ANALYSIS")
print("="*72)

t1_results = {}
NOTABLE_NUMBERS = {
    5: "Polybius width / FIVE seam / NDYAHR displacement count",
    6: "NDYAHR letter count",
    7: "KRYPTOS length / col7 width",
    8: "DEFECTOR length / K4 rows in legal pad",
    11: "BCL length",
    13: "ENE length / Bean d=13 anomaly",
    14: "grid half-height",
    24: "null count / Weltzeituhr facets",
    26: "alphabet size",
    31: "grid width",
    65: "Bean EQ position",
    73: "hypothesized CT length",
    97: "K4 carved length (prime)",
}

for l1, l2, pair_type in PAIRS:
    positions1 = NDYAHR_K4[l1]
    positions2 = NDYAHR_K4[l2]
    print(f"\n  Pair ({l1},{l2}) [{pair_type}]:")
    print(f"    {l1} positions: {positions1}")
    print(f"    {l2} positions: {positions2}")

    distances = {}
    for p1 in positions1:
        for p2 in positions2:
            d = abs(p2 - p1)
            signed_d = p2 - p1
            distances[(p1, p2)] = (d, signed_d)
            notable = NOTABLE_NUMBERS.get(d, "")
            tag = f" *** {notable}" if notable else ""
            print(f"    {l1}({p1}) <-> {l2}({p2}): distance = {d} (signed: {signed_d:+d}){tag}")

    t1_results[f"{l1}{l2}"] = distances

# Count how many distances are "notable"
all_distances = []
for pair_data in t1_results.values():
    for (p1, p2), (d, sd) in pair_data.items():
        all_distances.append(d)

notable_count = sum(1 for d in all_distances if d in NOTABLE_NUMBERS)
print(f"\n  Total pair distances: {len(all_distances)}")
print(f"  Notable distances: {notable_count}/{len(all_distances)}")

# Monte Carlo: how often do random positions produce this many notable hits?
import random
random.seed(42)
MC_TRIALS = 100000
mc_notable_counts = []
notable_set = set(NOTABLE_NUMBERS.keys())
for _ in range(MC_TRIALS):
    # Generate random positions matching NDYAHR counts
    rN = sorted(random.sample(range(97), 3))
    rD = sorted(random.sample(range(97), 3))
    rY = sorted(random.sample(range(97), 1))
    rA = sorted(random.sample(range(97), 4))
    rH = sorted(random.sample(range(97), 2))
    rR = sorted(random.sample(range(97), 4))
    count = 0
    for p1_list, p2_list in [(rN, rD), (rY, rA), (rH, rR)]:
        for p1 in p1_list:
            for p2 in p2_list:
                if abs(p2 - p1) in notable_set:
                    count += 1
    mc_notable_counts.append(count)

mc_mean = sum(mc_notable_counts) / len(mc_notable_counts)
mc_gte = sum(1 for c in mc_notable_counts if c >= notable_count) / len(mc_notable_counts)
print(f"\n  Monte Carlo (100K trials): mean notable = {mc_mean:.2f}, P(>={notable_count}) = {mc_gte:.4f}")
print(f"  Ratio to expected: {notable_count / mc_mean:.2f}x" if mc_mean > 0 else "  Expected = 0")

t1_results['notable_count'] = notable_count
t1_results['mc_p_value'] = mc_gte
t1_results['mc_mean'] = mc_mean
results['T1'] = {'notable_count': notable_count, 'mc_p_value': mc_gte, 'mc_mean': mc_mean}

# ══════════════════════════════════════════════════════════════════════════
# T2: PAIR DISTANCES AS CIPHER PARAMETERS
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*72)
print("T2: PAIR DISTANCES AS CIPHER PARAMETERS")
print("="*72)

# Collect all notable distances
notable_distances = sorted(set(d for d in all_distances if d in NOTABLE_NUMBERS))
all_unique_distances = sorted(set(all_distances))
print(f"  Notable distances: {notable_distances}")
print(f"  All unique distances: {all_unique_distances}")

best_t2 = 0
t2_configs = 0

# Test each distance as a Vigenere/Beaufort period on raw 97
for d in all_unique_distances:
    if d < 1 or d > 26:
        continue
    for variant in ['beau', 'vig']:
        for kw in ['KRYPTOS', 'DEFECTOR', 'SEVEN', 'NDYAHR']:
            kw_vals = [AZ_IDX[c] for c in kw]
            ct_vals = [AZ_IDX[c] for c in CT97]
            pt = []
            for i, cv in enumerate(ct_vals):
                kv = kw_vals[i % len(kw_vals)]
                if variant == 'beau':
                    pv = (kv - cv) % 26
                else:
                    pv = (cv - kv) % 26
                pt.append(ALPH[pv])
            pt_text = ''.join(pt)
            sc = score_crib_match(pt_text)
            t2_configs += 1
            if sc > best_t2:
                best_t2 = sc
                print(f"  NEW BEST: {sc}/24 - period={d}, kw={kw}, var={variant}")
                if sc >= 6:
                    print(f"    PT: {pt_text[:60]}...")

# Also test as col width for columnar transposition
for d in all_unique_distances:
    if d < 2 or d > 50:
        continue
    # Simple columnar: read by columns, width d
    n = len(CT97)
    nrows = (n + d - 1) // d
    padded = CT97 + 'X' * (nrows * d - n)
    # Read off by columns
    cols = [''.join(padded[r * d + c] for r in range(nrows) if r * d + c < n) for c in range(d)]
    reordered = ''.join(cols)[:n]
    sc = score_crib_match(reordered)
    t2_configs += 1
    if sc > best_t2:
        best_t2 = sc
        print(f"  NEW BEST (col trans): {sc}/24 - width={d}")

print(f"\n  T2 configs tested: {t2_configs}")
print(f"  T2 best score: {best_t2}/24")
results['T2'] = {'best_score': best_t2, 'configs': t2_configs}

# ══════════════════════════════════════════════════════════════════════════
# T3: PAIR OPERATIONS AS TRANSPOSITION SWAPS
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*72)
print("T3: PAIR OPERATIONS AS TRANSPOSITION SWAPS")
print("="*72)

best_t3 = 0
t3_configs = 0

# For each NDYAHR letter at position p, swap CT[p-1] with CT[p+1] (push neighbors apart)
# Or: swap the characters at the N and D positions themselves
# Try multiple interpretations

def apply_swaps(text, swap_list):
    """Apply a list of (i,j) swaps to text."""
    lst = list(text)
    for i, j in swap_list:
        if 0 <= i < len(lst) and 0 <= j < len(lst):
            lst[i], lst[j] = lst[j], lst[i]
    return ''.join(lst)

# Interpretation 1: Each NDYAHR letter at pos p -> swap(p-1, p+1)
swaps_1 = []
for letter in 'NDYAHR':
    for p in NDYAHR_K4[letter]:
        if p > 0 and p < 96:
            swaps_1.append((p-1, p+1))

modified = apply_swaps(CT97, swaps_1)
sc = score_crib_match(modified)
t3_configs += 1
print(f"  Interp 1 (swap neighbors of each NDYAHR): {sc}/24")
if sc > best_t3:
    best_t3 = sc

# Interpretation 2: Pair up N[i] with D[i] and swap those positions
for pairing_name, pair_assignments in [
    ("proximity", [(0,0), (1,1), (2,2)]),  # N[0]<->D[0], N[1]<->D[1], N[2]<->D[2]
    ("cross1", [(0,2), (1,1), (2,0)]),      # N[0]<->D[2], N[1]<->D[1], N[2]<->D[0]
]:
    nd_swaps = []
    for ni, di in pair_assignments:
        if ni < len(NDYAHR_K4['N']) and di < len(NDYAHR_K4['D']):
            nd_swaps.append((NDYAHR_K4['N'][ni], NDYAHR_K4['D'][di]))

    # Y-A pairs: Y has only 1 position, A has 4. Pair Y with each A.
    ya_combos = [(NDYAHR_K4['Y'][0], a) for a in NDYAHR_K4['A']]

    # H-R pairs: H has 2, R has 4. Try different pairings.
    hr_combos_all = [
        [(NDYAHR_K4['H'][0], NDYAHR_K4['R'][0]), (NDYAHR_K4['H'][1], NDYAHR_K4['R'][3])],
        [(NDYAHR_K4['H'][0], NDYAHR_K4['R'][1]), (NDYAHR_K4['H'][1], NDYAHR_K4['R'][2])],
        [(NDYAHR_K4['H'][0], NDYAHR_K4['R'][2]), (NDYAHR_K4['H'][1], NDYAHR_K4['R'][3])],
    ]

    for ya_swap in ya_combos:
        for hr_swaps in hr_combos_all:
            all_swaps = nd_swaps + [ya_swap] + hr_swaps
            modified = apply_swaps(CT97, all_swaps)
            sc = score_crib_match(modified)
            t3_configs += 1
            if sc > best_t3:
                best_t3 = sc
                print(f"  NEW BEST: {sc}/24 - ND={pairing_name}, YA=({ya_swap[0]},{ya_swap[1]}), HR={hr_swaps}")
            if sc >= 6:
                print(f"    Swaps: {all_swaps}")
                print(f"    Result: {modified[:60]}...")

# Interpretation 3: N pushes LEFT (swap p with p-1), D pushes RIGHT (swap p with p+1)
# Y pushes UP (grid: swap with position above), A pushes UP, H pushes RIGHT, R pushes UP-LEFT
swaps_3 = []
for letter in 'NDYAHR':
    dx, dy = LETTER_DIR[letter][1]
    for p in NDYAHR_K4[letter]:
        row, col = pos_to_grid(p)
        target_row = row + dy
        target_col = col + dx
        target_pos = grid_to_pos(target_row, target_col)
        if target_pos is not None:
            swaps_3.append((p, target_pos))
modified = apply_swaps(CT97, swaps_3)
sc = score_crib_match(modified)
t3_configs += 1
print(f"\n  Interp 3 (each letter swaps with grid-directional neighbor): {sc}/24")
if sc > best_t3:
    best_t3 = sc

# Interpretation 4: Swap each NDYAHR with its linear directional neighbor
# N->LEFT: p-1, D->RIGHT: p+1, Y->UP: p-31, A->UP: p-31, H->RIGHT: p+1, R->UP-LEFT: p-32
LINEAR_DIR = {'N': -1, 'D': +1, 'Y': -31, 'A': -31, 'H': +1, 'R': -32}
swaps_4 = []
for letter in 'NDYAHR':
    offset = LINEAR_DIR[letter]
    for p in NDYAHR_K4[letter]:
        target = p + offset
        if 0 <= target < N:
            swaps_4.append((p, target))
modified = apply_swaps(CT97, swaps_4)
sc = score_crib_match(modified)
t3_configs += 1
print(f"  Interp 4 (linear directional swaps): {sc}/24")
if sc > best_t3:
    best_t3 = sc

# Also try: apply directional swaps THEN decrypt with known ciphers
for variant_name, variant in [('beau', 'beau'), ('vig', 'vig')]:
    for kw in ['DEFECTOR', 'KRYPTOS', 'SEVEN']:
        for swap_list_name, swap_list in [('interp1', swaps_1), ('interp3', swaps_3), ('interp4', swaps_4)]:
            modified = apply_swaps(CT97, swap_list)
            pt = autokey_decrypt(modified, kw, variant, 'AZ')
            sc = score_crib_match(pt)
            t3_configs += 1
            if sc > best_t3:
                best_t3 = sc
                print(f"  NEW BEST (swap+decrypt): {sc}/24 - {swap_list_name}+{kw}:{variant}")
            if sc >= 10:
                print(f"    PT: {pt[:60]}...")

print(f"\n  T3 configs tested: {t3_configs}")
print(f"  T3 best score: {best_t3}/24")
results['T3'] = {'best_score': best_t3, 'configs': t3_configs}

# ══════════════════════════════════════════════════════════════════════════
# T4: PAIRED NULL MARKING
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*72)
print("T4: PAIRED NULL MARKING (directional neighbor of each NDYAHR = null)")
print("="*72)

best_t4 = 0
t4_configs = 0

# Multiple direction interpretations for each letter
# Format: letter -> offset in linear positions
DIR_SETS = {
    'standard': {'N': -1, 'D': +1, 'Y': -31, 'A': -31, 'H': +1, 'R': -32},
    'reversed': {'N': +1, 'D': -1, 'Y': +31, 'A': +31, 'H': -1, 'R': +32},
    'linear_simple': {'N': -1, 'D': +1, 'Y': -1, 'A': -1, 'H': +1, 'R': -1},  # all horizontal
    'self': {'N': 0, 'D': 0, 'Y': 0, 'A': 0, 'H': 0, 'R': 0},  # mark the letter itself
    'self_plus_dir': None,  # mark both self and directional neighbor
    'N_left_D_down': {'N': -1, 'D': +31, 'Y': -31, 'A': -31, 'H': +1, 'R': -32},
    'D_down_only': {'N': -1, 'D': +31, 'Y': -31, 'A': -31, 'H': +1, 'R': -31},
    'all_up': {'N': -31, 'D': -31, 'Y': -31, 'A': -31, 'H': -31, 'R': -31},
    'N_D_horiz_YA_vert': {'N': -1, 'D': +1, 'Y': -31, 'A': -31, 'H': +1, 'R': -31},
    # Pair-based: mark position BETWEEN the pair members
    'between': None,  # handled separately
    # Mark both neighbors (left + right for N/D, above + below for Y/A)
    'both_neighbors': None,
    # Grid-based
    'grid': None,  # use grid coords
}

def compute_marks(dir_set_name, dir_offsets=None):
    """Compute null marks for a given direction interpretation."""
    marks = set()

    if dir_set_name == 'self_plus_dir':
        base = {'N': -1, 'D': +1, 'Y': -31, 'A': -31, 'H': +1, 'R': -32}
        for letter in 'NDYAHR':
            for p in NDYAHR_K4[letter]:
                marks.add(p)  # self
                target = p + base[letter]
                if 0 <= target < N:
                    marks.add(target)
        return marks

    if dir_set_name == 'between':
        # For each pair, mark positions strictly between nearest pair members
        for l1, l2, _ in PAIRS:
            for p1 in NDYAHR_K4[l1]:
                # Find nearest l2 position
                dists = [(abs(p2 - p1), p2) for p2 in NDYAHR_K4[l2]]
                dists.sort()
                if dists:
                    _, nearest_p2 = dists[0]
                    lo, hi = min(p1, nearest_p2), max(p1, nearest_p2)
                    # Mark only the immediate neighbors of the pair endpoints
                    if lo + 1 < hi:
                        marks.add(lo + 1)
                    if hi - 1 > lo:
                        marks.add(hi - 1)
        return marks

    if dir_set_name == 'both_neighbors':
        for letter in 'NDYAHR':
            for p in NDYAHR_K4[letter]:
                if p > 0: marks.add(p - 1)
                if p < N - 1: marks.add(p + 1)
        return marks

    if dir_set_name == 'grid':
        # Use grid coordinates for direction
        for letter in 'NDYAHR':
            dx, dy = LETTER_DIR[letter][1]
            for p in NDYAHR_K4[letter]:
                row, col = pos_to_grid(p)
                tr, tc = row + dy, col + dx
                tp = grid_to_pos(tr, tc)
                if tp is not None:
                    marks.add(tp)
        return marks

    # Standard: use offsets dict
    if dir_offsets is None:
        return marks
    for letter in 'NDYAHR':
        for p in NDYAHR_K4[letter]:
            target = p + dir_offsets[letter]
            if 0 <= target < N:
                marks.add(target)
    return marks

print("\n  Direction interpretation sweep:")
for dir_name, dir_offsets in DIR_SETS.items():
    if dir_offsets is None and dir_name not in ('self_plus_dir', 'between', 'both_neighbors', 'grid'):
        continue
    marks = compute_marks(dir_name, dir_offsets)

    # Also add the NDYAHR positions themselves as optional additional nulls
    marks_with_self = marks | set(p for letter in 'NDYAHR' for p in NDYAHR_K4[letter])

    for mark_set_name, mark_set in [('marks_only', marks), ('marks+self', marks_with_self)]:
        # Filter to valid K4 positions
        valid_marks = mark_set & set(range(N))

        # Check overlap with consensus
        overlap = valid_marks & CONSENSUS_17
        n_marks = len(valid_marks)

        if n_marks < 5 or n_marks > 40:
            continue  # skip degenerate cases

        print(f"\n  [{dir_name}:{mark_set_name}] marks={n_marks}, consensus overlap={len(overlap)}/17")
        print(f"    Marked positions: {sorted(valid_marks)}")

        # If close to 24, try as null mask
        if 20 <= n_marks <= 28:
            mask_set = frozenset(valid_marks)
            # If not exactly 24, pad/trim
            if n_marks == 24:
                ct73 = extract_73(mask_set)
                for kw in ['DEFECTOR', 'KRYPTOS', 'SEVEN']:
                    for var in ['beau', 'vig']:
                        pt = autokey_decrypt(ct73, kw, var, 'AZ')
                        sc_free = score_candidate_free(pt)
                        sc = sc_free.total_score if hasattr(sc_free, 'total_score') else 0
                        t4_configs += 1
                        if sc > best_t4:
                            best_t4 = sc
                            print(f"    NEW BEST: {sc}/24 - {kw}:{var}")
                        if sc >= 6:
                            print(f"      PT: {pt[:60]}...")

        # Also try marking positions as nulls and scoring raw
        # (For any mark count, try removing those positions and decrypting the remainder)
        if 20 <= n_marks <= 28:
            remainder = ''.join(CT97[i] for i in range(N) if i not in valid_marks)
            if len(remainder) >= 60:
                for kw in ['DEFECTOR', 'KRYPTOS']:
                    for var in ['beau', 'vig']:
                        pt = autokey_decrypt(remainder, kw, var, 'AZ')
                        qg = qg_score(pt)
                        t4_configs += 1
                        # Also check free crib in the remainder
                        found_ene = ENE_WORD in pt
                        found_bcl = BCL_WORD in pt
                        if found_ene or found_bcl:
                            print(f"    *** CRIB FOUND in {kw}:{var}: ENE={found_ene} BCL={found_bcl}")
                            print(f"    PT: {pt}")

print(f"\n  T4 configs tested: {t4_configs}")
print(f"  T4 best score: {best_t4}/24")
results['T4'] = {'best_score': best_t4, 'configs': t4_configs}

# ══════════════════════════════════════════════════════════════════════════
# T5: COMPREHENSIVE FORCE-DIRECTION SWEEP
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*72)
print("T5: COMPREHENSIVE FORCE-DIRECTION SWEEP (consensus overlap)")
print("="*72)

# For each letter, try all 9 possible offsets: {-32,-31,-1,0,+1,+31,+32, -30, +30}
# That's 9^6 = 531,441 combinations. Too many. Instead try 5 choices per letter: {-1, +1, -31, +31, 0} = 5^6 = 15,625
OFFSET_CHOICES = [-32, -31, -1, 0, +1, +31, +32]

best_overlap = 0
best_overlap_config = None
t5_configs = 0

for offsets in iter_product(OFFSET_CHOICES, repeat=6):
    marks = set()
    for idx, letter in enumerate('NDYAHR'):
        off = offsets[idx]
        for p in NDYAHR_K4[letter]:
            target = p + off
            if 0 <= target < N:
                marks.add(target)

    overlap = len(marks & CONSENSUS_17)
    t5_configs += 1

    if overlap > best_overlap:
        best_overlap = overlap
        best_overlap_config = offsets
        letter_names = {-32: 'UL', -31: 'UP', -30: 'UR', -1: 'L', 0: 'SELF', 1: 'R', 31: 'DN', 32: 'DR'}
        config_str = ', '.join(f"{l}={letter_names.get(o, str(o))}" for l, o in zip('NDYAHR', offsets))
        print(f"  Overlap {overlap}/17: [{config_str}], marks={len(marks)}")

print(f"\n  T5 configs tested: {t5_configs}")
print(f"  Best consensus overlap: {best_overlap}/17")
if best_overlap_config:
    print(f"  Best config: {best_overlap_config}")

# Now test top overlap configs as cipher masks
# Find all configs with overlap >= best_overlap - 1
print(f"\n  Testing top overlap configs as null masks...")
best_t5_cipher = 0
t5_cipher_configs = 0

for offsets in iter_product(OFFSET_CHOICES, repeat=6):
    marks = set()
    for idx, letter in enumerate('NDYAHR'):
        off = offsets[idx]
        for p in NDYAHR_K4[letter]:
            target = p + off
            if 0 <= target < N:
                marks.add(target)

    overlap = len(marks & CONSENSUS_17)
    if overlap < best_overlap - 1:
        continue

    if 20 <= len(marks) <= 28:
        # Pad to 24 if needed using consensus positions not already in marks
        mask = set(marks)
        if len(mask) < 24:
            # Add consensus positions not yet in mask
            for cp in sorted(CONSENSUS_17):
                if cp not in mask:
                    mask.add(cp)
                    if len(mask) == 24:
                        break
        if len(mask) > 24:
            # Remove non-consensus positions
            non_cons = sorted(mask - CONSENSUS_17, reverse=True)
            for nc in non_cons:
                mask.discard(nc)
                if len(mask) == 24:
                    break

        if len(mask) == 24:
            ct73 = extract_73(frozenset(mask))
            for kw in ['DEFECTOR', 'KRYPTOS']:
                for var in ['beau', 'vig']:
                    pt = autokey_decrypt(ct73, kw, var, 'AZ')
                    sc_free = score_candidate_free(pt)
                    sc = sc_free.total_score if hasattr(sc_free, 'total_score') else 0
                    t5_cipher_configs += 1
                    if sc > best_t5_cipher:
                        best_t5_cipher = sc
                        print(f"    NEW BEST: {sc}/24 - overlap={overlap}, marks={len(marks)}, {kw}:{var}")

print(f"  T5 cipher configs: {t5_cipher_configs}")
print(f"  T5 best cipher score: {best_t5_cipher}/24")
results['T5'] = {
    'best_overlap': best_overlap,
    'best_overlap_config': list(best_overlap_config) if best_overlap_config else None,
    'best_cipher_score': best_t5_cipher,
    'configs': t5_configs,
    'cipher_configs': t5_cipher_configs,
}

# ══════════════════════════════════════════════════════════════════════════
# T6: PAIR OPERATIONS AS CIPHER TYPE SELECTORS
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*72)
print("T6: PAIR OPERATIONS AS CIPHER TYPE SELECTORS (3-region polyalphabetic)")
print("="*72)

best_t6 = 0
t6_configs = 0

# Assign each K4 position to nearest NDYAHR pair type
def assign_regions():
    """Assign each position to nearest NDYAHR pair type."""
    regions = {}  # pos -> pair_type (0=ND, 1=YA, 2=HR)
    for p in range(N):
        best_dist = 999
        best_type = 0
        for pair_idx, (l1, l2, _) in enumerate(PAIRS):
            for pos in NDYAHR_K4[l1] + NDYAHR_K4[l2]:
                d = abs(p - pos)
                if d < best_dist:
                    best_dist = d
                    best_type = pair_idx
        regions[p] = best_type
    return regions

regions = assign_regions()
region_counts = Counter(regions.values())
print(f"  Region assignment: ND={region_counts[0]}, YA={region_counts[1]}, HR={region_counts[2]}")

# Apply different cipher to each region
for kw in ['DEFECTOR', 'KRYPTOS', 'SEVEN']:
    for var_combo in [('beau', 'vig', 'beau'), ('vig', 'beau', 'vig'),
                       ('beau', 'beau', 'vig'), ('vig', 'vig', 'beau')]:
        ct_vals = [AZ_IDX[c] for c in CT97]
        kw_vals = [AZ_IDX[c] for c in kw]
        pt = []
        for i in range(N):
            kv = kw_vals[i % len(kw_vals)]
            cv = ct_vals[i]
            var = var_combo[regions[i]]
            if var == 'beau':
                pv = (kv - cv) % 26
            else:
                pv = (cv - kv) % 26
            pt.append(ALPH[pv])
        pt_text = ''.join(pt)
        sc = score_crib_match(pt_text)
        t6_configs += 1
        if sc > best_t6:
            best_t6 = sc
            print(f"  NEW BEST: {sc}/24 - {kw}, regions={var_combo}")

# Also try: NDYAHR positions themselves get different cipher
for kw in ['DEFECTOR', 'KRYPTOS', 'SEVEN']:
    ct_vals = [AZ_IDX[c] for c in CT97]
    kw_vals = [AZ_IDX[c] for c in kw]
    # At NDYAHR positions, shift by the pair-specific distance
    for shift_nd, shift_ya, shift_hr in [(26, 7, 8), (5, 7, 6), (7, 31, 14), (8, 26, 65)]:
        pt = []
        for i in range(N):
            cv = ct_vals[i]
            kv = kw_vals[i % len(kw_vals)]
            ch = CT97[i]
            extra = 0
            if ch in ('N', 'D'):
                extra = shift_nd
            elif ch in ('Y', 'A'):
                extra = shift_ya
            elif ch in ('H', 'R'):
                extra = shift_hr
            pv = (kv - cv + extra) % 26  # Beaufort + extra shift for NDYAHR
            pt.append(ALPH[pv])
        pt_text = ''.join(pt)
        sc = score_crib_match(pt_text)
        t6_configs += 1
        if sc > best_t6:
            best_t6 = sc
            print(f"  NEW BEST: {sc}/24 - {kw}:beau+shifts({shift_nd},{shift_ya},{shift_hr})")

print(f"\n  T6 configs tested: {t6_configs}")
print(f"  T6 best score: {best_t6}/24")
results['T6'] = {'best_score': best_t6, 'configs': t6_configs}

# ══════════════════════════════════════════════════════════════════════════
# T7: BETWEEN-PAIR REGIONS AS NULL ZONES
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*72)
print("T7: BETWEEN-PAIR REGIONS AS NULL ZONES")
print("="*72)

best_t7 = 0
t7_configs = 0

# For each pair, try: positions between nearest pair members are nulls
# Also: positions adjacent to pair members are nulls (1 or 2 positions each side)

for radius in [1, 2, 3]:
    # Mark positions within 'radius' of any NDYAHR position
    null_marks = set()
    for letter in 'NDYAHR':
        for p in NDYAHR_K4[letter]:
            for offset in range(-radius, radius + 1):
                target = p + offset
                if 0 <= target < N and target != p:
                    null_marks.add(target)

    overlap = len(null_marks & CONSENSUS_17)
    print(f"\n  Radius {radius}: {len(null_marks)} marks, consensus overlap={overlap}/17")

    # Also include the NDYAHR positions themselves
    with_self = null_marks | set(p for letter in 'NDYAHR' for p in NDYAHR_K4[letter])
    overlap2 = len(with_self & CONSENSUS_17)
    print(f"  Radius {radius}+self: {len(with_self)} marks, consensus overlap={overlap2}/17")

# Between each matched pair
for l1, l2, ptype in PAIRS:
    p1s = sorted(NDYAHR_K4[l1])
    p2s = sorted(NDYAHR_K4[l2])

    # Match by proximity: sort all positions, pair closest
    all_pos = [(p, l1) for p in p1s] + [(p, l2) for p in p2s]
    all_pos.sort()

    # Try all bijective pairings where each l1 matches one l2
    # For simplicity, pair by sorted order
    min_len = min(len(p1s), len(p2s))
    for p_idx in range(min_len):
        lo, hi = min(p1s[p_idx], p2s[p_idx]), max(p1s[p_idx], p2s[p_idx])
        between = set(range(lo + 1, hi))
        overlap = len(between & CONSENSUS_17)
        if len(between) > 0:
            print(f"  {l1}({p1s[p_idx]})<->{l2}({p2s[p_idx]}): between={len(between)} pos, consensus overlap={overlap}/17")
            t7_configs += 1

print(f"\n  T7 configs tested: {t7_configs}")
print(f"  T7 best score: {best_t7}/24")
results['T7'] = {'best_score': best_t7, 'configs': t7_configs}

# ══════════════════════════════════════════════════════════════════════════
# T8: PAIR DISTANCES AS KEY VECTOR
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*72)
print("T8: PAIR DISTANCES AS KEY VECTOR")
print("="*72)

best_t8 = 0
t8_configs = 0

# Collect shortest/notable distance per pair
nd_dists = []
for p1 in NDYAHR_K4['N']:
    for p2 in NDYAHR_K4['D']:
        nd_dists.append(abs(p2 - p1))

ya_dists = []
for p1 in NDYAHR_K4['Y']:
    for p2 in NDYAHR_K4['A']:
        ya_dists.append(abs(p2 - p1))

hr_dists = []
for p1 in NDYAHR_K4['H']:
    for p2 in NDYAHR_K4['R']:
        hr_dists.append(abs(p2 - p1))

print(f"  N-D distances: {sorted(nd_dists)}")
print(f"  Y-A distances: {sorted(ya_dists)}")
print(f"  H-R distances: {sorted(hr_dists)}")

# Try: min distance from each pair as shift key
for nd in nd_dists:
    for ya in ya_dists:
        for hr in hr_dists:
            key_vals = [nd % 26, ya % 26, hr % 26]
            if len(key_vals) < 3:
                continue
            ct_vals = [AZ_IDX[c] for c in CT97]
            # As period-3 Beaufort key
            for variant in ['beau', 'vig']:
                pt = []
                for i, cv in enumerate(ct_vals):
                    kv = key_vals[i % 3]
                    if variant == 'beau':
                        pv = (kv - cv) % 26
                    else:
                        pv = (cv - kv) % 26
                    pt.append(ALPH[pv])
                pt_text = ''.join(pt)
                sc = score_crib_match(pt_text)
                t8_configs += 1
                if sc > best_t8:
                    best_t8 = sc
                    print(f"  NEW BEST: {sc}/24 - dists=({nd},{ya},{hr}), var={variant}")

            # As period-6 key (each pair distance repeated)
            key6 = [nd % 26, nd % 26, ya % 26, ya % 26, hr % 26, hr % 26]
            for variant in ['beau', 'vig']:
                pt = []
                for i, cv in enumerate(ct_vals):
                    kv = key6[i % 6]
                    if variant == 'beau':
                        pv = (kv - cv) % 26
                    else:
                        pv = (cv - kv) % 26
                    pt.append(ALPH[pv])
                pt_text = ''.join(pt)
                sc = score_crib_match(pt_text)
                t8_configs += 1
                if sc > best_t8:
                    best_t8 = sc
                    print(f"  NEW BEST: {sc}/24 - dists6=({nd},{nd},{ya},{ya},{hr},{hr}), var={variant}")

# Also try the notable distance values as direct key letters
notable_vals = [5, 6, 7, 8, 14, 26, 31, 65]
for combo in combinations(notable_vals, 3):
    key3 = [v % 26 for v in combo]
    ct_vals = [AZ_IDX[c] for c in CT97]
    for variant in ['beau', 'vig']:
        pt = []
        for i, cv in enumerate(ct_vals):
            kv = key3[i % 3]
            if variant == 'beau':
                pv = (kv - cv) % 26
            else:
                pv = (cv - kv) % 26
            pt.append(ALPH[pv])
        pt_text = ''.join(pt)
        sc = score_crib_match(pt_text)
        t8_configs += 1
        if sc > best_t8:
            best_t8 = sc
            print(f"  NEW BEST: {sc}/24 - notable combo={combo}, var={variant}")

print(f"\n  T8 configs tested: {t8_configs}")
print(f"  T8 best score: {best_t8}/24")
results['T8'] = {'best_score': best_t8, 'configs': t8_configs}

# ══════════════════════════════════════════════════════════════════════════
# T9: POLYBIUS COORDINATE SYSTEM FROM PAIR POSITIONS
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*72)
print("T9: POLYBIUS COORDINATE SYSTEM FROM PAIR POSITIONS")
print("="*72)

best_t9 = 0
t9_configs = 0

# N,D define horizontal axis (3 positions each = 3 divisions)
# Y,A define vertical axis (1+4=5 positions)
# H,R define diagonal (2+4=6 positions)

# Try: N positions define column boundaries, D positions define row boundaries
# This creates a coordinate grid within K4
nd_sorted = sorted(NDYAHR_K4['N'] + NDYAHR_K4['D'])
ya_sorted = sorted(NDYAHR_K4['Y'] + NDYAHR_K4['A'])
hr_sorted = sorted(NDYAHR_K4['H'] + NDYAHR_K4['R'])

print(f"  N+D positions (horizontal): {nd_sorted}")
print(f"  Y+A positions (vertical): {ya_sorted}")
print(f"  H+R positions (diagonal): {hr_sorted}")

# Segment K4 by N+D positions
segments_nd = []
prev = 0
for bp in nd_sorted + [N]:
    if bp > prev:
        segments_nd.append((prev, bp))
    prev = bp + 1
print(f"  N+D segments: {segments_nd} (lengths: {[e-s for s,e in segments_nd]})")

# Try: alternate segments are null/real
for start_null in [True, False]:
    nulls = set()
    for idx, (s, e) in enumerate(segments_nd):
        is_null = (idx % 2 == 0) == start_null
        if is_null:
            for p in range(s, e):
                nulls.add(p)
    overlap = len(nulls & CONSENSUS_17)
    print(f"  Alternating ND segments (start_null={start_null}): {len(nulls)} nulls, overlap={overlap}/17")
    t9_configs += 1

# Same for Y+A segments
segments_ya = []
prev = 0
for bp in ya_sorted + [N]:
    if bp > prev:
        segments_ya.append((prev, bp))
    prev = bp + 1
print(f"  Y+A segments: {segments_ya} (lengths: {[e-s for s,e in segments_ya]})")

for start_null in [True, False]:
    nulls = set()
    for idx, (s, e) in enumerate(segments_ya):
        is_null = (idx % 2 == 0) == start_null
        if is_null:
            for p in range(s, e):
                nulls.add(p)
    overlap = len(nulls & CONSENSUS_17)
    print(f"  Alternating YA segments (start_null={start_null}): {len(nulls)} nulls, overlap={overlap}/17")
    t9_configs += 1

# Polybius-like: position p gets coordinate (nearest N/D distance, nearest Y/A distance)
# Then map coordinates to null/real
for p in range(5):  # sample
    nd_dist = min(abs(p - q) for q in nd_sorted) if nd_sorted else 99
    ya_dist = min(abs(p - q) for q in ya_sorted) if ya_sorted else 99
    hr_dist = min(abs(p - q) for q in hr_sorted) if hr_sorted else 99
    print(f"  pos {p}: ND_dist={nd_dist}, YA_dist={ya_dist}, HR_dist={hr_dist}")

# Try: positions with ND_dist <= threshold are nulls
for threshold in range(1, 6):
    nulls = set()
    for p in range(N):
        nd_dist = min(abs(p - q) for q in nd_sorted)
        if nd_dist <= threshold:
            nulls.add(p)
    overlap = len(nulls & CONSENSUS_17)
    if 15 <= len(nulls) <= 35:
        print(f"  ND_dist<={threshold}: {len(nulls)} nulls, overlap={overlap}/17")
        t9_configs += 1

print(f"\n  T9 configs tested: {t9_configs}")
print(f"  T9 best score: {best_t9}/24")
results['T9'] = {'best_score': best_t9, 'configs': t9_configs}

# ══════════════════════════════════════════════════════════════════════════
# T10: COMBINED BEST - Top masks + DEFECTOR:AZ_beau autokey
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*72)
print("T10: COMBINED - Top null masks from all tests + DEFECTOR:AZ_beau autokey")
print("="*72)

best_t10 = 0
t10_configs = 0

# Collect all promising masks from the tests
candidate_masks = []

# From T4: all direction interpretations that produced 24 marks
for dir_name, dir_offsets in DIR_SETS.items():
    if dir_offsets is None and dir_name not in ('self_plus_dir', 'between', 'both_neighbors', 'grid'):
        continue
    marks = compute_marks(dir_name, dir_offsets)
    valid_marks = marks & set(range(N))
    if len(valid_marks) == 24:
        candidate_masks.append((dir_name, frozenset(valid_marks)))
    # Pad to 24 with consensus
    if 18 <= len(valid_marks) <= 23:
        padded = set(valid_marks)
        for cp in sorted(CONSENSUS_17):
            if cp not in padded:
                padded.add(cp)
                if len(padded) == 24:
                    break
        if len(padded) == 24:
            candidate_masks.append((f"{dir_name}_padded", frozenset(padded)))

# Also add: NDYAHR self-positions as part of mask
ndyahr_positions_in_k4 = set()
for letter in 'NDYAHR':
    ndyahr_positions_in_k4.update(NDYAHR_K4[letter])
print(f"  NDYAHR positions in K4: {sorted(ndyahr_positions_in_k4)} ({len(ndyahr_positions_in_k4)} total)")

# The 17 NDYAHR positions + 7 from consensus = 24?
ndyahr_plus_consensus = ndyahr_positions_in_k4 | CONSENSUS_17
overlap_with_cons = ndyahr_positions_in_k4 & CONSENSUS_17
print(f"  NDYAHR overlap with consensus: {len(overlap_with_cons)}/17")
print(f"  NDYAHR + consensus: {len(ndyahr_plus_consensus)} positions")

# Try: NDYAHR positions ARE 17 of the nulls, fill remaining 7 from consensus
if len(ndyahr_positions_in_k4) <= 24:
    mask = set(ndyahr_positions_in_k4)
    # Add consensus positions not already in mask
    for cp in sorted(CONSENSUS_17):
        if cp not in mask:
            mask.add(cp)
            if len(mask) == 24:
                break
    # If still not 24, add more from consensus neighborhood
    if len(mask) < 24:
        for cp in sorted(CONSENSUS_17):
            for offset in [+1, -1, +2, -2]:
                target = cp + offset
                if 0 <= target < N and target not in mask:
                    mask.add(target)
                    if len(mask) == 24:
                        break
            if len(mask) == 24:
                break
    if len(mask) == 24:
        candidate_masks.append(("ndyahr_self_padded", frozenset(mask)))

# Consensus only (baseline)
cons_padded = set(CONSENSUS_17)
# Need 7 more from known masks
for p in MASKS_24[0]:
    if p not in cons_padded:
        cons_padded.add(p)
        if len(cons_padded) == 24:
            break
candidate_masks.append(("consensus_mask0", frozenset(cons_padded)))

print(f"\n  Testing {len(candidate_masks)} candidate masks with DEFECTOR:AZ_beau autokey...")

for mask_name, mask_set in candidate_masks:
    ct73 = extract_73(mask_set)
    # DEFECTOR:AZ_beau autokey
    pt = autokey_decrypt(ct73, 'DEFECTOR', 'beau', 'AZ')
    # Score with free crib search
    sc_free = score_candidate_free(pt)
    sc = sc_free.total_score if hasattr(sc_free, 'total_score') else 0
    qg = qg_score(pt)
    t10_configs += 1

    # Also check anchored cribs if mask preserves crib positions
    anchored = score_crib_match(pt)

    if sc > best_t10 or sc >= 6:
        best_t10 = max(best_t10, sc)
        print(f"  [{mask_name}] free_crib={sc}, anchored={anchored}, qg={qg:.3f}")
        if sc >= 8:
            print(f"    PT: {pt[:60]}...")
            print(f"    Mask: {sorted(mask_set)}")

    # Also try with col7 transposition
    # Simple col7: read CT73 in column-major order with width 7
    n73 = len(ct73)
    nrows = (n73 + 6) // 7
    padded = ct73 + 'X' * (nrows * 7 - n73)
    col7_text = ''
    for c in range(7):
        for r in range(nrows):
            pos = r * 7 + c
            if pos < n73:
                col7_text += padded[pos]
    col7_text = col7_text[:n73]

    pt2 = autokey_decrypt(col7_text, 'DEFECTOR', 'beau', 'AZ')
    sc2_free = score_candidate_free(pt2)
    sc2 = sc2_free.total_score if hasattr(sc2_free, 'total_score') else 0
    t10_configs += 1
    if sc2 > best_t10 or sc2 >= 6:
        best_t10 = max(best_t10, sc2)
        print(f"  [{mask_name}+col7] free_crib={sc2}, qg={qg_score(pt2):.3f}")

print(f"\n  T10 configs tested: {t10_configs}")
print(f"  T10 best score: {best_t10}/24")
results['T10'] = {'best_score': best_t10, 'configs': t10_configs}

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
elapsed = time.time() - t0
print("\n" + "="*72)
print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
print("="*72)

total_configs = sum(results[k].get('configs', 0) + results[k].get('cipher_configs', 0)
                     for k in results if isinstance(results[k], dict))
overall_best = max(results[k].get('best_score', results[k].get('best_cipher_score', 0))
                    for k in results if isinstance(results[k], dict))

print(f"  Total configs tested: {total_configs}")
print(f"  Overall best score: {overall_best}/24")

for k in sorted(results.keys()):
    v = results[k]
    if isinstance(v, dict):
        score = v.get('best_score', v.get('best_cipher_score', 'N/A'))
        configs = v.get('configs', 0) + v.get('cipher_configs', 0)
        print(f"  {k}: best={score}/24, configs={configs}")

results['summary'] = {
    'total_configs': total_configs,
    'overall_best': overall_best,
    'elapsed_seconds': elapsed,
}

# Save results
out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'ndyahr_paired_forces.json')
with open(out_path, 'w') as f:
    json.dump({k: v for k, v in results.items() if k != 'T1' or not isinstance(v, dict) or 'mc_p_value' in v},
              f, indent=2, default=str)
print(f"\nResults saved to {out_path}")
