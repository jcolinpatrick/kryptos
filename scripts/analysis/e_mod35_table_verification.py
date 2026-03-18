#!/usr/bin/env python3
"""
Mod-35 Table Derivation — Verification and Statistical Significance

Verifies the exact matches found by e_mod35_table_derivation.py and computes
their statistical significance.

Key question: if we have 26 occupied cells (13 null-ish, 13 real) and
the cipher output has 15-18 distinct values, how many random 5-letter words
would produce an exact separation?

Also: investigate TOWER, CHART, LAYER for thematic significance.
"""
import sys
import os
import json
import random
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, KRYPTOS_ALPHABET, ALPH

# ══════════════════════════════════════════════════════════════════════════
PALETTE = frozenset('BGIKOWZ')
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = {c: i for i, c in enumerate(ALPH)}
KRYPTOS_AZ = [AZ_IDX[c] for c in 'KRYPTOS']
KRYPTOS_KA = [KA_IDX[c] for c in 'KRYPTOS']

palette_positions = sorted(p for p in range(CT_LEN) if CT[p] in PALETTE)
labels = {p: p in CONSENSUS_NULLS for p in palette_positions}

cell_positions = defaultdict(list)
for p in palette_positions:
    cell_positions[(p % 7, p % 5)].append(p)

target_table = {}
for r in range(7):
    for c in range(5):
        positions = cell_positions.get((r, c), [])
        if not positions:
            target_table[(r, c)] = None
        else:
            null_count = sum(1 for p in positions if labels[p])
            real_count = len(positions) - null_count
            if null_count > 0 and real_count == 0:
                target_table[(r, c)] = True
            elif real_count > 0 and null_count == 0:
                target_table[(r, c)] = False
            else:
                target_table[(r, c)] = 'mixed'

occupied_cells = [(r, c) for r in range(7) for c in range(5) if target_table[(r, c)] is not None]
# For separation check: treat mixed as null (13 null-ish, 13 real-ish)
target_nullish = set()
target_realish = set()
for (r, c) in occupied_cells:
    if target_table[(r, c)] is True or target_table[(r, c)] == 'mixed':
        target_nullish.add((r, c))
    else:
        target_realish.add((r, c))

print(f"Null-ish cells: {len(target_nullish)}, Real-ish cells: {len(target_realish)}")
assert len(target_nullish) == 13
assert len(target_realish) == 13

# ══════════════════════════════════════════════════════════════════════════
# STEP 1: Verify each exact match in detail
# ══════════════════════════════════════════════════════════════════════════
print("=" * 90)
print("VERIFICATION OF EXACT MATCHES")
print("=" * 90)

def verify_match(word, alpha_name, variant_name, expected_null_letters):
    """Verify a match and print the full table."""
    if alpha_name == 'AZ':
        alpha = ALPH
        alpha_idx = AZ_IDX
        kw_vals = KRYPTOS_AZ
    else:
        alpha = KA
        alpha_idx = KA_IDX
        kw_vals = KRYPTOS_KA

    w_vals = [alpha_idx[c] for c in word]

    variant_funcs = {
        'vig': lambda k, p: (k - p) % 26,
        'beau': lambda k, p: (k + p) % 26,
        'vbeau': lambda k, p: (p - k) % 26,
    }
    func = variant_funcs[variant_name]

    print(f"\n{'='*60}")
    print(f"KRYPTOS x {word} ({alpha_name}_{variant_name})")
    print(f"{'='*60}")

    # Print the full 7x5 output table
    print(f"\nOutput letters (row=KRYPTOS, col={word}):")
    print(f"{'':>10}", end="")
    for ci, c in enumerate(word):
        print(f"  {c}({alpha_idx[c]:>2})", end="")
    print()

    for ri in range(7):
        kw_letter = 'KRYPTOS'[ri]
        print(f"  {kw_letter}({kw_vals[ri]:>2}):", end="")
        for ci in range(5):
            out_idx = func(kw_vals[ri], w_vals[ci])
            out_letter = alpha[out_idx]
            print(f"     {out_letter}  ", end="")
        print()

    # Classify
    null_letters = set(expected_null_letters) if expected_null_letters else set()
    correct = 0
    total = 0
    for (r, c) in occupied_cells:
        out_idx = func(kw_vals[r], w_vals[c])
        out_letter = alpha[out_idx]
        predicted_null = out_letter in null_letters
        actual = (r, c) in target_nullish
        ok = predicted_null == actual
        if ok:
            correct += 1
        total += 1

    print(f"\nNull letters: {sorted(null_letters)}")
    print(f"Accuracy: {correct}/{total}")
    return correct == total

# Verify all 8 matches
matches = [
    ('TOWER', 'AZ', 'vig', ['C','D','N','T','V','Y','Z']),
    ('TOWER', 'AZ', 'vbeau', ['B','C','F','H','N','X','Y']),
    ('CHART', 'AZ', 'beau', ['D','I','M','P','Q','T','U','Y']),
    ('LAYER', 'KA', 'vig', ['D','H','I','J','K','P','Q','R','Y','Z']),
    ('LAYER', 'KA', 'vbeau', ['D','E','F','J','K','R','S','W','X','Z']),
]

for word, alpha, variant, null_letters in matches:
    ok = verify_match(word, alpha, variant, null_letters)
    print(f"VERIFIED: {ok}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 2: Statistical significance — how many random 5-letter words match?
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("STATISTICAL SIGNIFICANCE: RANDOM WORD SEARCH")
print("=" * 90)

# For AZ Vigenere: how many of the 26^5 = 11,881,376 possible 5-letter words
# produce perfect separation?

# Rather than enumerate all 12M, we'll:
# 1. Sample 1M random words and check
# 2. Also exhaustively check for important variants

random.seed(42)
N_RANDOM = 500_000  # 500K random words per variant
hits_by_variant = {}

for alpha_name, alpha_idx_map, alpha_str, kw_vals in [
    ('AZ', AZ_IDX, ALPH, KRYPTOS_AZ),
    ('KA', KA_IDX, KA, KRYPTOS_KA),
]:
    for variant_name, variant_func in [
        ('vig', lambda k, p: (k - p) % 26),
        ('beau', lambda k, p: (k + p) % 26),
        ('vbeau', lambda k, p: (p - k) % 26),
    ]:
        key = f"{alpha_name}_{variant_name}"
        hits = 0

        for _ in range(N_RANDOM):
            w_vals = [random.randint(0, 25) for _ in range(5)]

            # Compute outputs for all occupied cells
            outputs = {}
            for (r, c) in occupied_cells:
                out_idx = variant_func(kw_vals[r], w_vals[c])
                out_letter = alpha_str[out_idx]
                outputs[(r, c)] = out_letter

            # Check if null-ish and real-ish cells have disjoint output sets
            null_out = set(outputs[(r, c)] for (r, c) in target_nullish)
            real_out = set(outputs[(r, c)] for (r, c) in target_realish)

            if not (null_out & real_out):
                hits += 1

        hits_by_variant[key] = hits
        estimated_total = int(hits / N_RANDOM * 26**5)
        print(f"  {key}: {hits}/{N_RANDOM} random words produce perfect separation "
              f"(estimated {estimated_total} of {26**5:,} total = "
              f"{hits/N_RANDOM*100:.3f}%)")

# ══════════════════════════════════════════════════════════════════════════
# STEP 3: Is the null letter set "natural" (e.g., first/last half of alphabet)?
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("STEP 3: ANALYSIS OF NULL LETTER SETS")
print("=" * 90)

# For each match, analyze the null letter set
for word, alpha, variant, null_letters in matches:
    if alpha == 'AZ':
        alpha_idx_map = AZ_IDX
    else:
        alpha_idx_map = KA_IDX

    null_indices = sorted(alpha_idx_map[c] for c in null_letters)
    print(f"\n{word} ({alpha}_{variant}):")
    print(f"  Null letters: {sorted(null_letters)}")
    print(f"  Null indices ({alpha}): {null_indices}")
    print(f"  Count: {len(null_letters)} null / {26 - len(null_letters)} real")

    # Is it contiguous in the alphabet?
    ranges = []
    start = null_indices[0]
    end = start
    for idx in null_indices[1:]:
        if idx == end + 1:
            end = idx
        else:
            ranges.append((start, end))
            start = idx
            end = idx
    ranges.append((start, end))
    print(f"  Contiguous ranges: {ranges}")

    # Is it first half / second half?
    first_half = sum(1 for i in null_indices if i < 13)
    second_half = len(null_indices) - first_half
    print(f"  First half (0-12): {first_half}, Second half (13-25): {second_half}")

    # Is it even/odd?
    evens = sum(1 for i in null_indices if i % 2 == 0)
    odds = len(null_indices) - evens
    print(f"  Even indices: {evens}, Odd indices: {odds}")

    # Check if null_letters = PALETTE
    if set(null_letters) == PALETTE:
        print(f"  *** NULL LETTERS = PALETTE! ***")
    overlap_with_palette = set(null_letters) & PALETTE
    print(f"  Overlap with palette {PALETTE}: {overlap_with_palette}")

    # Check if null_letters are the "unused" letters in some keyword
    for kw_name, kw in [('KRYPTOS', 'KRYPTOS'), ('DEFECTOR', 'DEFECTOR'),
                          ('PALIMPSEST', 'PALIMPSEST'), ('ABSCISSA', 'ABSCISSA')]:
        kw_set = set(kw)
        if set(null_letters) == kw_set:
            print(f"  *** NULL LETTERS = {kw_name} ***")
        if set(null_letters) <= kw_set:
            print(f"  Null letters SUBSET of {kw_name}")
        not_in_kw = set(null_letters) - kw_set
        in_kw = set(null_letters) & kw_set
        print(f"  In {kw_name}: {sorted(in_kw)}, NOT in {kw_name}: {sorted(not_in_kw)}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 4: Investigate TOWER thematically
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("STEP 4: THEMATIC ANALYSIS OF MATCHING WORDS")
print("=" * 90)

print("""
TOWER:
  - Kryptos is a TOWER-like structure (vertical copper plates)
  - The Berliner Fernsehturm (TV Tower) is visible from the Weltzeituhr (Berlin Clock)
  - CIA headquarters has literal towers
  - Tower = T,O,W,E,R — contains palette letters O, W
  - AZ values: T=19, O=14, W=22, E=4, R=17
  - KA values: T=4, O=5, W=23, E=11, R=1

CHART:
  - Sanborn's "coding chart" / "working chart" = 28x31 master grid
  - "What's on the chart?" is literally a K4 question
  - CHART = C,H,A,R,T — none in palette
  - AZ values: C=2, H=7, A=0, R=17, T=19

LAYER:
  - "Pull up one layer, come to the next" (Sanborn)
  - Two LAYERS of encryption
  - LAYER = L,A,Y,E,R — none in palette
  - KA values: L=17, A=7, Y=2, E=11, R=1

All three words are thematically resonant with the K4 puzzle.
""")

# ══════════════════════════════════════════════════════════════════════════
# STEP 5: Relationships between TOWER, CHART, LAYER
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("STEP 5: ALGEBRAIC RELATIONSHIPS BETWEEN MATCHING WORDS")
print("=" * 90)

# Are TOWER and CHART related by a simple transformation?
tower_az = [AZ_IDX[c] for c in 'TOWER']
chart_az = [AZ_IDX[c] for c in 'CHART']
layer_az = [AZ_IDX[c] for c in 'LAYER']
layer_ka = [KA_IDX[c] for c in 'LAYER']

print(f"TOWER AZ: {tower_az} ({','.join('TOWER')})")
print(f"CHART AZ: {chart_az} ({','.join('CHART')})")
print(f"LAYER AZ: {layer_az} ({','.join('LAYER')})")
print(f"LAYER KA: {layer_ka}")

# Differences
print(f"\nTOWER - CHART (mod 26): {[(t-c)%26 for t,c in zip(tower_az, chart_az)]}")
print(f"TOWER + CHART (mod 26): {[(t+c)%26 for t,c in zip(tower_az, chart_az)]}")
print(f"TOWER - LAYER (mod 26): {[(t-l)%26 for t,l in zip(tower_az, layer_az)]}")
print(f"CHART - LAYER (mod 26): {[(c-l)%26 for c,l in zip(chart_az, layer_az)]}")

# Is CHART = Vig(TOWER, key) for some key?
vig_key = [(c - t) % 26 for t, c in zip(tower_az, chart_az)]
print(f"\nVig key TOWER->CHART: {vig_key} = {''.join(ALPH[k] for k in vig_key)}")
beau_key = [(c + t) % 26 for t, c in zip(tower_az, chart_az)]
print(f"Beau key TOWER->CHART: {beau_key} = {''.join(ALPH[k] for k in beau_key)}")

# Does TOWER relate to KRYPTOS?
print(f"\nKRYPTOS AZ: {KRYPTOS_AZ}")
# Any letter overlap?
print(f"TOWER letters in KRYPTOS: {set('TOWER') & set('KRYPTOS')}")
print(f"CHART letters in KRYPTOS: {set('CHART') & set('KRYPTOS')}")
print(f"LAYER letters in KRYPTOS: {set('LAYER') & set('KRYPTOS')}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 6: Exhaustive search — ALL 5-letter words that produce exact match
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("STEP 6: EXHAUSTIVE SEARCH — ALL MATCHING 5-LETTER WORDS")
print("=" * 90)

# For each variant, systematically find all matching words by
# checking the constraint column by column.

# For AZ Vigenere: output at (r,c) = (KW_AZ[r] - w[c]) mod 26
# For exact separation: null_outputs INTERSECT real_outputs = empty set
# This means: for each column c, the 13 outputs at null rows and
# 13 outputs at real rows must be disjoint sets (globally, across all cols)

# This is expensive to enumerate exhaustively for 26^5, but we can
# use the column-independence: each column c adds some outputs to
# the null and real sets. We need the global union to be disjoint.

# Actually, the outputs at different cells are independent, so we need
# ALL null cell outputs to be from a set S, and ALL real cell outputs
# from the complement of S.

# For a given word, the output at (r,c) is determined. We need to find
# a partition of the output values into two sets such that all null cells
# map to one set and all real cells to the other.

# This is equivalent to: the function from cell to output value must be
# such that no output value appears at BOTH a null cell and a real cell.

# For each variant, enumerate all words systematically

for alpha_name, alpha_str, kw_vals in [
    ('AZ', ALPH, KRYPTOS_AZ),
    ('KA', KA, KRYPTOS_KA),
]:
    for variant_name, variant_func in [
        ('vig', lambda k, p: (k - p) % 26),
        ('beau', lambda k, p: (k + p) % 26),
        ('vbeau', lambda k, p: (p - k) % 26),
    ]:
        key = f"{alpha_name}_{variant_name}"
        matching_words = []

        # For efficiency: for each of the 26^5 words, check if outputs at
        # null cells and real cells are disjoint.
        # 26^5 = 11.8M -- feasible but slow. Let's optimize:
        # For each column value w[c], the outputs at null/real rows in that column
        # are fixed. Pre-compute: for each column c and each possible w[c] value,
        # what output values appear at null rows and real rows.

        # Pre-compute per-column constraints
        null_rows = {}
        real_rows = {}
        for c in range(5):
            null_rows[c] = [r for (r2, c2) in target_nullish if c2 == c for r in [r2]]
            real_rows[c] = [r for (r2, c2) in target_realish if c2 == c for r in [r2]]

        # For each column c and each value w[c] in 0-25:
        # null_outputs[c][wc] = set of output values at null rows
        # real_outputs[c][wc] = set of output values at real rows
        col_null_outs = {}
        col_real_outs = {}
        for c in range(5):
            col_null_outs[c] = {}
            col_real_outs[c] = {}
            for wc in range(26):
                n_outs = set(variant_func(kw_vals[r], wc) for r in null_rows[c])
                r_outs = set(variant_func(kw_vals[r], wc) for r in real_rows[c])
                col_null_outs[c][wc] = n_outs
                col_real_outs[c][wc] = r_outs

        # Now enumerate all 26^5 combinations
        # For each, the global null set = union of all col null outs
        # Global real set = union of all col real outs
        # Must be disjoint
        count = 0
        for w0 in range(26):
            n0 = col_null_outs[0][w0]
            r0 = col_real_outs[0][w0]
            for w1 in range(26):
                n01 = n0 | col_null_outs[1][w1]
                r01 = r0 | col_real_outs[1][w1]
                if n01 & r01:
                    continue  # Early prune
                for w2 in range(26):
                    n012 = n01 | col_null_outs[2][w2]
                    r012 = r01 | col_real_outs[2][w2]
                    if n012 & r012:
                        continue
                    for w3 in range(26):
                        n0123 = n012 | col_null_outs[3][w3]
                        r0123 = r012 | col_real_outs[3][w3]
                        if n0123 & r0123:
                            continue
                        for w4 in range(26):
                            n_all = n0123 | col_null_outs[4][w4]
                            r_all = r0123 | col_real_outs[4][w4]
                            if not (n_all & r_all):
                                word = ''.join(alpha_str[v] for v in [w0,w1,w2,w3,w4])
                                matching_words.append(word)
                                count += 1

        print(f"\n{key}: {count} exact-match words out of {26**5:,} = {count/26**5*100:.4f}%")
        if count <= 100:
            for w in matching_words:
                print(f"  {w}")
        else:
            print(f"  First 30: {matching_words[:30]}")
            print(f"  Last 10: {matching_words[-10:]}")
            # Check if any are English words
            # Load wordlist
            wl_path = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'english.txt')
            try:
                with open(wl_path) as f:
                    english = set(w.strip().upper() for w in f if len(w.strip()) == 5)
                eng_matches = [w for w in matching_words if w in english]
                print(f"  English words: {eng_matches[:50]}")
            except:
                print(f"  (Could not load English wordlist)")

# ══════════════════════════════════════════════════════════════════════════
# STEP 7: What is the SIMPLEST null-letter rule?
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("STEP 7: SIMPLEST NULL-LETTER THRESHOLD RULE")
print("=" * 90)

# For TOWER AZ_vig: null_letters = {C,D,N,T,V,Y,Z} = {2,3,13,19,21,24,25}
# real_letters = {B,F,K,L,O,P,W,X} = {1,5,10,11,14,15,22,23}
# Is there a simple threshold? Null if value >= T or value in specific range?

for word, alpha, variant, null_letters in matches:
    if alpha == 'AZ':
        idx = AZ_IDX
    else:
        idx = KA_IDX
    null_vals = sorted(idx[c] for c in null_letters)
    real_vals = sorted(idx[c] for c in set(ALPH) - set(null_letters) if c in idx)
    max_null = max(null_vals)
    min_null = min(null_vals)
    max_real = max(real_vals)
    min_real = min(real_vals)
    print(f"\n{word} ({alpha}_{variant}):")
    print(f"  Null indices: {null_vals}")
    print(f"  Real indices (all 26 - null): {real_vals}")
    print(f"  Null range: [{min_null}, {max_null}]")
    print(f"  Real range: [{min_real}, {max_real}]")
    # Check simple threshold
    for T in range(1, 26):
        pred_null = set(i for i in range(26) if i < T)
        pred_real = set(range(26)) - pred_null
        if set(null_vals) <= pred_null and set(real_vals) <= pred_real:
            print(f"  Simple threshold: null if output_idx < {T}")
        if set(null_vals) <= pred_real and set(real_vals) <= pred_null:
            print(f"  Simple threshold: null if output_idx >= {T}")
    # Check mod 2
    null_mod2 = [v % 2 for v in null_vals]
    print(f"  Null values mod 2: {null_mod2}")

# ══════════════════════════════════════════════════════════════════════════
# SAVE
# ══════════════════════════════════════════════════════════════════════════
print("\n\nDONE.")
