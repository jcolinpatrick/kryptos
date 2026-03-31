#!/usr/bin/env python3
"""
Cipher: Beaufort (analysis)
Family: analysis
Status: active
Keyspace: N/A (analytical)
Last run: 2026-03-15
Best score: N/A
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

"""E-KEYSTREAM-FORENSICS: Deep analysis of the 24 Beaufort keystream values.

Uses the consensus null mask + col7 transposition to extract 73-char CT,
then computes Beaufort keystream at all 24 crib positions. Analyses:
  1. Basic properties (freqs, IC, palette)
  2. Periodicity (0-conflict periods)
  3. Recurrence relations (Gromark/Fibonacci)
  4. Running key patterns (K1-K3 PT, keywords)
  5. Position-dependent key functions
  6. DEFECTOR autokey comparison (15/24 match)
  7. Correction vector analysis (the 9 mismatches)
  8. Beaufort encryption of position
  9. Vigenere keystream comparison
 10. Bean constraint verification
"""

import json, os, time
from collections import Counter
from itertools import product

# ── Constants ────────────────────────────────────────────────────────────
CT97 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
N2L = {i: c for i, c in enumerate(AZ)}

# Consensus null mask (17 positions at 100% consensus + best-fit for remaining 7)
# From MEMORY.md: 17 positions at 100% consensus across all 6 distinct 15/24 masks
# {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}
# User specified full 24-null mask:
MASK = [0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 39, 40, 52, 55, 58, 59, 74, 75, 78, 84, 85, 88, 94, 96]
MASK_SET = set(MASK)

assert len(MASK) == 24, f"Mask must have 24 positions, got {len(MASK)}"

# Cribs (0-indexed in CT97 space)
ENE_START = 21
ENE_TEXT = "EASTNORTHEAST"
BCL_START = 63
BCL_TEXT = "BERLINCLOCK"

CRIB_DICT_97 = {}
for i, ch in enumerate(ENE_TEXT):
    CRIB_DICT_97[ENE_START + i] = ch
for i, ch in enumerate(BCL_TEXT):
    CRIB_DICT_97[BCL_START + i] = ch

# K1-K3 plaintexts
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"

# Thematic keywords
KEYWORDS = {
    'KRYPTOS': [10, 17, 24, 15, 19, 14, 18],
    'DEFECTOR': [3, 4, 5, 4, 2, 19, 14, 17],
    'ABSCISSA': [0, 1, 18, 2, 8, 18, 18, 0],
    'PALIMPSEST': [15, 0, 11, 8, 12, 15, 18, 4, 18, 19],
    'SEVEN': [18, 4, 21, 4, 13],
    'KOMPASS': [10, 14, 12, 15, 0, 18, 18],
    'COLOPHON': [2, 14, 11, 14, 15, 7, 14, 13],
    'PARALLAX': [15, 0, 17, 0, 11, 11, 0, 23],
    'BERLIN': [1, 4, 17, 11, 8, 13],
    'CLOCK': [2, 11, 14, 2, 10],
    'BERLINCLOCK': [1, 4, 17, 11, 8, 13, 2, 11, 14, 2, 10],
}

# KA alphabet
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_I2N = {c: i for i, c in enumerate(KA)}

# ── Step 1: Extract 73 chars (remove 24 nulls) ──────────────────────
ct73_chars = []
ct97_to_ct73 = {}  # maps CT97 position -> CT73 position
ct73_to_ct97 = {}  # maps CT73 position -> CT97 position
j = 0
for i in range(97):
    if i not in MASK_SET:
        ct73_chars.append(CT97[i])
        ct97_to_ct73[i] = j
        ct73_to_ct97[j] = i
        j += 1

CT73 = ''.join(ct73_chars)
assert len(CT73) == 73, f"Expected 73 chars, got {len(CT73)}"

print("=" * 80)
print("E-KEYSTREAM-FORENSICS: Beaufort Keystream Deep Analysis")
print("=" * 80)
print(f"\nCT97:  {CT97}")
print(f"CT73:  {CT73}")
print(f"Nulls: {sorted(MASK)}")

# ── Step 2: Apply inverse col7 transposition ─────────────────────────
# Ascending columnar transposition width 7
# Write into rows of width 7, read columns in ascending order (0,1,2,3,4,5,6)
# For ascending order, the "reading" is: read col 0 top-to-bottom, then col 1, etc.
# This IS the forward transposition.
# The INVERSE = write into columns, read rows.

W = 7
n = len(CT73)
nrows = (n + W - 1) // W  # = 11
nshort = nrows * W - n     # = 11*7 - 73 = 4 short columns

# Ascending col order = [0,1,2,3,4,5,6]
# Columns 0-2 have nrows=11 chars each (full), columns 3-6 have nrows-1=10 chars each (short)
# Wait: the SHORT columns are the LAST ones in the reading order.
# With ascending order [0,1,2,3,4,5,6] and 4 short columns:
# Columns 0,1,2 have 11 chars (first 3 columns)
# Columns 3,4,5,6 have 10 chars (last 4 columns)
# Total = 3*11 + 4*10 = 33 + 40 = 73 ✓

# Forward transposition: write CT73 into grid by rows, read by columns
# Inverse: given CT73 as column-reading, reconstruct row-reading

# Build grid from column reading (CT73 = columns concatenated)
col_lengths = []
for c in range(W):
    if c < W - nshort:
        col_lengths.append(nrows)
    else:
        col_lengths.append(nrows - 1)

# CT73 = col0 chars + col1 chars + col2 chars + ...
# Parse into columns
grid = [[None]*nrows for _ in range(W)]
idx = 0
for c in range(W):
    for r in range(col_lengths[c]):
        grid[c][r] = CT73[idx]
        idx += 1

assert idx == 73, f"Used {idx} chars, expected 73"

# Read by rows to get the intermediate text (pre-transposition)
intermediate = []
for r in range(nrows):
    for c in range(W):
        if grid[c][r] is not None:
            intermediate.append(grid[c][r])

INTER = ''.join(intermediate)
assert len(INTER) == 73, f"Intermediate length {len(INTER)}, expected 73"

print(f"\nIntermediate (after inv col7): {INTER}")

# Build mappings: position in intermediate -> position in CT73
# Forward col trans: grid[r][c] at row-pos r*W+c -> col-pos = sum(col_lengths[:c]) + r
# Intermediate pos p = r*W+c (row reading)
# CT73 pos = column reading position
inter_to_ct73 = {}
ct73_to_inter = {}
row_idx = 0
for r in range(nrows):
    for c in range(W):
        if r < col_lengths[c]:
            # This cell exists
            col_offset = sum(col_lengths[:c])
            ct73_pos = col_offset + r
            inter_pos = row_idx
            inter_to_ct73[inter_pos] = ct73_pos
            ct73_to_inter[ct73_pos] = inter_pos
            row_idx += 1

# ── Crib positions in intermediate space ─────────────────────────────
# Cribs are at CT97 positions. After null removal -> CT73 positions. After inv col7 -> intermediate positions.
print("\n--- Crib Position Mapping ---")
print(f"{'CT97':>6} {'CT73':>6} {'Inter':>6} {'CT':>3} {'PT':>3}")

crib_inter_positions = {}  # intermediate_pos -> (ct_char, pt_char)
for pos97 in sorted(CRIB_DICT_97.keys()):
    if pos97 in ct97_to_ct73:
        pos73 = ct97_to_ct73[pos97]
        # The CT73 is the column-read text. The intermediate is the row-read text.
        # We need to find where pos73 in CT73 maps to in intermediate
        if pos73 in ct73_to_inter:
            pos_inter = ct73_to_inter[pos73]
            ct_char = INTER[pos_inter]
            pt_char = CRIB_DICT_97[pos97]
            crib_inter_positions[pos_inter] = (ct_char, pt_char)
            print(f"{pos97:>6} {pos73:>6} {pos_inter:>6}   {ct_char}   {pt_char}")
        else:
            print(f"{pos97:>6} {pos73:>6}   ???  (no inter mapping)")
    else:
        print(f"{pos97:>6}   NULL  (in mask)")

# ── Step 3: Compute Beaufort keystream ───────────────────────────────
print("\n" + "=" * 80)
print("SECTION 1: BASIC PROPERTIES")
print("=" * 80)

# Beaufort: K = (CT + PT) mod 26
# Vigenere: K = (CT - PT) mod 26
beau_keystream = {}
vig_keystream = {}
vbeau_keystream = {}

for pos_inter, (ct_ch, pt_ch) in sorted(crib_inter_positions.items()):
    ct_val = I2N[ct_ch]
    pt_val = I2N[pt_ch]
    beau_k = (ct_val + pt_val) % 26
    vig_k = (ct_val - pt_val) % 26
    vbeau_k = (pt_val - ct_val) % 26
    beau_keystream[pos_inter] = beau_k
    vig_keystream[pos_inter] = vig_k
    vbeau_keystream[pos_inter] = vbeau_k

sorted_positions = sorted(beau_keystream.keys())
beau_values = [beau_keystream[p] for p in sorted_positions]
vig_values = [vig_keystream[p] for p in sorted_positions]

print("\n--- 1a. All 24 (position, keystream_value) pairs ---")
print(f"{'Pos':>4} {'Beau_K':>7} {'Letter':>7} {'Vig_K':>7} {'VigLet':>7} {'CT':>4} {'PT':>4}")
for pos in sorted_positions:
    bk = beau_keystream[pos]
    vk = vig_keystream[pos]
    ct_ch, pt_ch = crib_inter_positions[pos]
    print(f"{pos:>4} {bk:>7} {N2L[bk]:>7} {vk:>7} {N2L[vk]:>7} {ct_ch:>4} {pt_ch:>4}")

print(f"\nBeau keystream letters: {''.join(N2L[beau_keystream[p]] for p in sorted_positions)}")
print(f"Vig  keystream letters: {''.join(N2L[vig_keystream[p]] for p in sorted_positions)}")

# Frequency analysis
beau_freq = Counter(beau_values)
print(f"\n--- 1b. Letter frequencies (Beaufort keystream) ---")
for val, count in sorted(beau_freq.items()):
    print(f"  {N2L[val]}({val:>2}): {'#' * count} {count}")

# IC of 24-value keystream
n_ks = len(beau_values)
ic_num = sum(c * (c - 1) for c in beau_freq.values())
ic_den = n_ks * (n_ks - 1)
ic = ic_num / ic_den if ic_den > 0 else 0
print(f"\n--- 1c. IC of 24-value Beaufort keystream: {ic:.4f} ---")
print(f"  Random IC (26 letters): {1/26:.4f}")
print(f"  English IC: 0.0667")
print(f"  {'ABOVE' if ic > 1/26 else 'BELOW'} random expectation")

# Palette letters
PALETTE = set('BGIKOWZ')
palette_count = sum(1 for v in beau_values if N2L[v] in PALETTE)
print(f"\n--- 1d. Palette letters {{B,G,I,K,O,W,Z}} count: {palette_count}/24 ---")
for p in sorted_positions:
    bk = beau_keystream[p]
    letter = N2L[bk]
    flag = " <-- PALETTE" if letter in PALETTE else ""
    print(f"  pos {p:>2}: {letter}{flag}")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SECTION 2: PERIODICITY")
print("=" * 80)

for ks_name, ks_dict in [("Beaufort", beau_keystream), ("Vigenere", vig_keystream)]:
    print(f"\n--- {ks_name} keystream period consistency ---")
    for p in range(1, 27):
        residue_vals = {}
        conflicts = 0
        for pos in sorted_positions:
            r = pos % p
            if r in residue_vals:
                if residue_vals[r] != ks_dict[pos]:
                    conflicts += 1
            else:
                residue_vals[r] = ks_dict[pos]
        n_residues = len(residue_vals)
        status = "*** CONSISTENT ***" if conflicts == 0 else f"{conflicts} conflicts"
        if conflicts == 0 or conflicts <= 2:
            print(f"  period {p:>2}: {status} ({n_residues} residues used)")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SECTION 3: RECURRENCE RELATIONS")
print("=" * 80)

# Build a dense position→value map
# But positions are sparse. We need contiguous runs.
# ENE crib positions in intermediate space:
ene_inter = sorted([p for p in sorted_positions if p in crib_inter_positions and
                     any(ct97 in range(21, 34) for ct97, v73 in [(ct97, ct97_to_ct73.get(ct97))
                     for ct97 in range(21, 34)] if v73 is not None and ct73_to_inter.get(v73) == p)])

# Actually, let's rebuild this cleanly
ene_inter_pos = []
bcl_inter_pos = []
for ct97_pos in range(21, 34):
    if ct97_pos in ct97_to_ct73:
        ct73_pos = ct97_to_ct73[ct97_pos]
        if ct73_pos in ct73_to_inter:
            ene_inter_pos.append(ct73_to_inter[ct73_pos])

for ct97_pos in range(63, 74):
    if ct97_pos in ct97_to_ct73:
        ct73_pos = ct97_to_ct73[ct97_pos]
        if ct73_pos in ct73_to_inter:
            bcl_inter_pos.append(ct73_to_inter[ct73_pos])

print(f"\nENE intermediate positions: {ene_inter_pos}")
print(f"BCL intermediate positions: {bcl_inter_pos}")

# Check recurrence: k[pos_i] = (k[pos_i-a] + k[pos_i-b]) mod M
# Since positions are sparse, use the 73-position keystream space
# We can only check where we HAVE values

print("\n--- Recurrence check: k[i] = (k[i-a] + k[i-b]) mod M ---")
print("    Testing all (a,b) with 1<=a<b<=15 and M in {5,7,8,10,13,26}")

best_recurrences = []
for M in [5, 7, 8, 10, 13, 26]:
    for a in range(1, 16):
        for b in range(a + 1, 16):
            matches = 0
            total_checkable = 0
            for pos in sorted_positions:
                src_a = pos - a
                src_b = pos - b
                if src_a in beau_keystream and src_b in beau_keystream:
                    total_checkable += 1
                    predicted = (beau_keystream[src_a] + beau_keystream[src_b]) % M
                    if predicted == beau_keystream[pos] % M:
                        matches += 1
            if total_checkable >= 3 and matches >= 3:
                best_recurrences.append((matches, total_checkable, a, b, M))

best_recurrences.sort(key=lambda x: (-x[0], x[1]))
print(f"\n  Top recurrence fits (≥3 matches, ≥3 checkable):")
for matches, total, a, b, M in best_recurrences[:15]:
    pct = matches / total * 100 if total > 0 else 0
    print(f"    a={a}, b={b}, M={M}: {matches}/{total} ({pct:.0f}%)")

# Standard Gromark: k[i] = (k[i-5] + k[i-4]) mod 10
print("\n--- Standard Gromark check: k[i] = (k[i-5] + k[i-4]) mod 10 ---")
gm_matches = 0
gm_total = 0
for pos in sorted_positions:
    if pos - 5 in beau_keystream and pos - 4 in beau_keystream:
        gm_total += 1
        predicted = (beau_keystream[pos - 5] + beau_keystream[pos - 4]) % 10
        actual = beau_keystream[pos] % 10
        match_str = "MATCH" if predicted == actual else "miss"
        print(f"    pos {pos}: k[{pos-5}]={beau_keystream[pos-5]} + k[{pos-4}]={beau_keystream[pos-4]} "
              f"= {(beau_keystream[pos-5]+beau_keystream[pos-4])%10} mod 10, actual={actual} [{match_str}]")
        if predicted == actual:
            gm_matches += 1
print(f"  Gromark: {gm_matches}/{gm_total}")

# Also check subtraction recurrence: k[i] = (k[i-a] - k[i-b]) mod M
print("\n--- Subtraction recurrence: k[i] = (k[i-a] - k[i-b]) mod M ---")
best_sub_rec = []
for M in [5, 7, 8, 10, 13, 26]:
    for a in range(1, 16):
        for b in range(1, 16):
            if a == b:
                continue
            matches = 0
            total_checkable = 0
            for pos in sorted_positions:
                src_a = pos - a
                src_b = pos - b
                if src_a in beau_keystream and src_b in beau_keystream:
                    total_checkable += 1
                    predicted = (beau_keystream[src_a] - beau_keystream[src_b]) % M
                    if predicted == beau_keystream[pos] % M:
                        matches += 1
            if total_checkable >= 3 and matches >= 3:
                best_sub_rec.append((matches, total_checkable, a, b, M))

best_sub_rec.sort(key=lambda x: (-x[0], x[1]))
for matches, total, a, b, M in best_sub_rec[:10]:
    pct = matches / total * 100 if total > 0 else 0
    print(f"    a={a}, b={b}, M={M}: {matches}/{total} ({pct:.0f}%)")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SECTION 4: RUNNING KEY PATTERNS")
print("=" * 80)

# Check if the 24 Beaufort keystream values match any substring of K1/K2/K3 PT
def check_running_key(ks_values, ks_positions, source_text, source_name):
    """Check if keystream matches source at any offset."""
    source_nums = [I2N[c] for c in source_text]
    best_offset = -1
    best_matches = 0

    for offset in range(-len(source_text), len(source_text)):
        matches = 0
        for i, pos in enumerate(ks_positions):
            src_idx = pos + offset
            if 0 <= src_idx < len(source_nums):
                if source_nums[src_idx] == ks_values[i]:
                    matches += 1
        if matches > best_matches:
            best_matches = matches
            best_offset = offset

    return best_offset, best_matches

print("\n--- 4a. K1/K2/K3 PT as running key ---")
for name, text in [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT)]:
    offset, matches = check_running_key(beau_values, sorted_positions, text, name)
    print(f"  {name}: best {matches}/24 at offset {offset}")

# Also try K1+K2+K3 concatenated
K123 = K1_PT + K2_PT + K3_PT
offset, matches = check_running_key(beau_values, sorted_positions, K123, "K1+K2+K3")
print(f"  K1+K2+K3: best {matches}/24 at offset {offset}")

# Check cyclic keywords
print("\n--- 4b. Cyclic keyword matches ---")
for kw_name, kw_vals in KEYWORDS.items():
    L = len(kw_vals)
    best_m = 0
    best_shift = 0
    for shift in range(L):
        matches = 0
        for i, pos in enumerate(sorted_positions):
            predicted = kw_vals[(pos + shift) % L]
            if predicted == beau_values[i]:
                matches += 1
        if matches > best_m:
            best_m = matches
            best_shift = shift
    print(f"  {kw_name:>15} (L={L}): best {best_m}/24 at shift {best_shift}")

# Check KA-mapped keywords
print("\n--- 4c. KA alphabet mapped cyclic keywords ---")
for kw_name in ['KRYPTOS', 'DEFECTOR', 'KOMPASS', 'COLOPHON']:
    kw_ka = [KA_I2N[c] for c in kw_name]
    L = len(kw_ka)
    best_m = 0
    best_shift = 0
    for shift in range(L):
        matches = 0
        for i, pos in enumerate(sorted_positions):
            predicted = kw_ka[(pos + shift) % L]
            if predicted == beau_values[i]:
                matches += 1
        if matches > best_m:
            best_m = matches
            best_shift = shift
    print(f"  {kw_name}:KA (L={L}): best {best_m}/24 at shift {best_shift}")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SECTION 5: POSITION-DEPENDENT KEY")
print("=" * 80)

# k = (a*pos + b) mod 26
print("\n--- 5a. Linear: k = (a*pos + b) mod 26 ---")
best_linear = (0, 0, 0)
for a in range(26):
    for b in range(26):
        matches = sum(1 for i, pos in enumerate(sorted_positions)
                      if (a * pos + b) % 26 == beau_values[i])
        if matches > best_linear[0]:
            best_linear = (matches, a, b)
print(f"  Best: {best_linear[0]}/24 at a={best_linear[1]}, b={best_linear[2]}")

# k = (a*pos^2 + b*pos + c) mod 26
print("\n--- 5b. Quadratic: k = (a*pos^2 + b*pos + c) mod 26 ---")
best_quad = (0, 0, 0, 0)
for a in range(26):
    for b in range(26):
        # Determine c from first position
        pos0 = sorted_positions[0]
        c_val = (beau_values[0] - a * pos0 * pos0 - b * pos0) % 26
        matches = sum(1 for i, pos in enumerate(sorted_positions)
                      if (a * pos * pos + b * pos + c_val) % 26 == beau_values[i])
        if matches > best_quad[0]:
            best_quad = (matches, a, b, c_val)
print(f"  Best: {best_quad[0]}/24 at a={best_quad[1]}, b={best_quad[2]}, c={best_quad[3]}")

# k = KRYPTOS[pos%7] via KA
print("\n--- 5c. KA[pos mod L] patterns ---")
for L in range(3, 15):
    kw_name = 'KA'
    for start in range(26):
        matches = sum(1 for i, pos in enumerate(sorted_positions)
                      if (start + pos) % 26 == beau_values[i])
        if matches >= 5:
            print(f"  KA shift: (pos + {start}) mod 26 -> {matches}/24")

# k = KRYPTOS[pos%7]
print("\n--- 5d. KRYPTOS[pos%7] (AZ values) ---")
kw = KEYWORDS['KRYPTOS']
for shift in range(7):
    matches = 0
    for i, pos in enumerate(sorted_positions):
        if kw[(pos + shift) % 7] == beau_values[i]:
            matches += 1
    if matches >= 3:
        print(f"  shift={shift}: {matches}/24")

# k = DEFECTOR[pos%8]
print("\n--- 5e. DEFECTOR[pos%8] (periodic — the 15/24 model) ---")
kw_def = KEYWORDS['DEFECTOR']
for shift in range(8):
    matches = 0
    match_positions = []
    miss_positions = []
    for i, pos in enumerate(sorted_positions):
        predicted = kw_def[(pos + shift) % 8]
        if predicted == beau_values[i]:
            matches += 1
            match_positions.append(pos)
        else:
            miss_positions.append((pos, beau_values[i], predicted))
    if matches >= 5:
        print(f"  shift={shift}: {matches}/24")
        if matches >= 10:
            print(f"    Matching positions: {match_positions}")
            print(f"    Miss positions (pos, actual, predicted):")
            for pos, actual, predicted in miss_positions:
                delta = (actual - predicted) % 26
                print(f"      pos {pos:>2}: actual={N2L[actual]}({actual}), predicted={N2L[predicted]}({predicted}), delta={delta} ({N2L[delta]})")

# Combined keyword functions
print("\n--- 5f. Combined: (KRYPTOS[pos%7] + SEVEN[pos%5]) mod 26 ---")
kw_k = KEYWORDS['KRYPTOS']
kw_s = KEYWORDS['SEVEN']
for op_name, op in [("add", lambda a, b: (a + b) % 26),
                     ("sub", lambda a, b: (a - b) % 26),
                     ("xor", lambda a, b: a ^ b)]:
    best_m = 0
    for sk in range(7):
        for ss in range(5):
            matches = sum(1 for i, pos in enumerate(sorted_positions)
                          if op(kw_k[(pos + sk) % 7], kw_s[(pos + ss) % 5]) == beau_values[i])
            if matches > best_m:
                best_m = matches
    print(f"  KRYPTOS {op_name} SEVEN: best {best_m}/24")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SECTION 6: DEFECTOR AUTOKEY COMPARISON")
print("=" * 80)

# DEFECTOR:AZ Beaufort autokey model
# In Beaufort autokey (PT-autokey): K[i] = PT[i-L] for i >= L, K[0..L-1] = keyword
# In Beaufort: PT[i] = (K[i] - CT_inter[i]) mod 26
# Actually for Beaufort decryption: PT = (K - C) mod 26
# With PT-autokey: K[i] = PT[i-8] for i >= 8
# Key priming: K[0..7] = DEFECTOR = [3,4,5,4,2,19,14,17]

# We need to simulate the DEFECTOR:AZ_beau autokey on the intermediate text
defector_vals = [I2N[c] for c in "DEFECTOR"]
inter_nums = [I2N[c] for c in INTER]
L = 8  # DEFECTOR length

# Beaufort PT-autokey decryption
# K[i] = primer[i] for i < L
# K[i] = PT[i-L] for i >= L
# PT[i] = (K[i] - C[i]) mod 26

defector_pt = []
defector_key = []
for i in range(73):
    if i < L:
        k = defector_vals[i]
    else:
        k = defector_pt[i - L]
    defector_key.append(k)
    pt_val = (k - inter_nums[i]) % 26
    defector_pt.append(pt_val)

print(f"\nDEFECTOR:AZ_beau autokey PT: {''.join(N2L[v] for v in defector_pt)}")
print(f"DEFECTOR:AZ_beau autokey key: {''.join(N2L[v] for v in defector_key)}")

# Compare autokey key to the correct Beaufort keystream at crib positions
# Beaufort key: K[i] = (C[i] + PT[i]) mod 26
# But for autokey, the key IS generated from PT... so the "correct" key and the
# autokey key should match WHERE the autokey generates the right PT.

# The Beaufort keystream we computed = (CT_inter + PT_crib) mod 26 at crib positions
# The DEFECTOR autokey key = defector_key[i]
# They match when DEFECTOR autokey produces the correct PT at position i

print(f"\n--- 6a. Which 15 of 24 match DEFECTOR:AZ_beau autokey? ---")
print(f"{'Pos':>4} {'Correct_K':>10} {'Defector_K':>11} {'Match':>6} {'Delta':>6} {'D_Letter':>9}")

match_count = 0
match_positions = []
miss_positions = []
deltas = []
all_comparisons = []

for pos in sorted_positions:
    correct_k = beau_keystream[pos]
    defector_k = defector_key[pos]
    is_match = correct_k == defector_k
    delta = (correct_k - defector_k) % 26

    all_comparisons.append({
        'pos': pos,
        'correct_k': correct_k,
        'defector_k': defector_k,
        'match': is_match,
        'delta': delta
    })

    if is_match:
        match_count += 1
        match_positions.append(pos)
        status = "YES"
    else:
        miss_positions.append(pos)
        deltas.append((pos, delta))
        status = "NO"

    print(f"{pos:>4} {N2L[correct_k]:>6}({correct_k:>2}) {N2L[defector_k]:>7}({defector_k:>2}) {status:>6} {delta:>6} {N2L[delta]:>9}")

print(f"\nTotal matches: {match_count}/24")
print(f"Match positions: {match_positions}")
print(f"Miss positions:  {miss_positions}")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SECTION 7: CORRECTION VECTOR ANALYSIS")
print("=" * 80)

print(f"\n--- 7a. The {len(deltas)} delta values (correct - DEFECTOR) mod 26 ---")
delta_vals = [d for _, d in deltas]
delta_letters = [N2L[d] for d in delta_vals]
print(f"  Delta positions: {[p for p, _ in deltas]}")
print(f"  Delta values:    {delta_vals}")
print(f"  Delta letters:   {''.join(delta_letters)}")

# Is delta constant?
if len(set(delta_vals)) == 1:
    print(f"\n  *** CONSTANT DELTA: {delta_vals[0]} ({N2L[delta_vals[0]]}) ***")
else:
    print(f"\n  Delta is NOT constant ({len(set(delta_vals))} distinct values)")
    delta_freq = Counter(delta_vals)
    print(f"  Delta frequency: {dict(delta_freq)}")
    most_common_delta = delta_freq.most_common(1)[0]
    print(f"  Most common: {most_common_delta[0]} ({N2L[most_common_delta[0]]}) appears {most_common_delta[1]}x")

# Is delta periodic?
print(f"\n--- 7b. Delta periodicity ---")
for p in range(2, 14):
    residue_map = {}
    conflicts = 0
    for pos, delta in deltas:
        r = pos % p
        if r in residue_map:
            if residue_map[r] != delta:
                conflicts += 1
        else:
            residue_map[r] = delta
    if conflicts == 0:
        print(f"  period {p}: CONSISTENT (residues: {dict(residue_map)})")

# Is delta related to known keywords?
print(f"\n--- 7c. Delta as keyword ---")
# Check if delta_letters spell something or contain a recognizable pattern
print(f"  Delta word: {''.join(delta_letters)}")
# Check if it's a cyclic keyword applied to miss positions
for kw_name, kw_vals in KEYWORDS.items():
    L = len(kw_vals)
    for shift in range(L):
        matches = sum(1 for i, (pos, delta) in enumerate(deltas)
                      if kw_vals[(pos + shift) % L] == delta)
        if matches >= 4:
            print(f"  {kw_name} at shift {shift}: {matches}/{len(deltas)} deltas match")

# Check delta against intermediate text
print(f"\n--- 7d. Delta vs intermediate CT values ---")
for pos, delta in deltas:
    inter_val = I2N[INTER[pos]]
    print(f"  pos {pos}: delta={delta}({N2L[delta]}), inter_CT={inter_val}({INTER[pos]}), "
          f"diff(delta-CT)={(delta-inter_val)%26}, sum(delta+CT)={(delta+inter_val)%26}")

# Check if delta = f(position)
print(f"\n--- 7e. Delta as function of position ---")
for a in range(26):
    for b in range(26):
        matches = sum(1 for pos, delta in deltas if (a * pos + b) % 26 == delta)
        if matches >= len(deltas) - 1:
            print(f"  delta = ({a}*pos + {b}) mod 26: {matches}/{len(deltas)} match")

# Check delta = DEFECTOR_PT[pos] related
print(f"\n--- 7f. Delta vs DEFECTOR autokey PT ---")
for pos, delta in deltas:
    def_pt_val = defector_pt[pos]
    print(f"  pos {pos}: delta={delta}({N2L[delta]}), DEF_PT={def_pt_val}({N2L[def_pt_val]}), "
          f"diff={(delta-def_pt_val)%26}, sum={(delta+def_pt_val)%26}")

# Check if delta = correct_PT - DEFECTOR_PT
print(f"\n--- 7g. What the DEFECTOR model thinks PT is vs what cribs say ---")
for pos in sorted_positions:
    ct_ch, pt_correct = crib_inter_positions[pos]
    pt_correct_val = I2N[pt_correct]
    def_pt_val = defector_pt[pos]
    comp = all_comparisons[[c['pos'] for c in all_comparisons].index(pos)]
    match_str = "MATCH" if comp['match'] else "MISS"
    pt_delta = (pt_correct_val - def_pt_val) % 26
    print(f"  pos {pos:>2}: crib_PT={pt_correct}({pt_correct_val:>2}), DEF_PT={N2L[def_pt_val]}({def_pt_val:>2}), "
          f"PT_delta={pt_delta:>2}({N2L[pt_delta]}), key_{match_str}")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SECTION 8: BEAUFORT ENCRYPTION OF POSITION")
print("=" * 80)

# k[i] = (KEY - i) mod 26 for constant KEY
print(f"\n--- 8a. k = (KEY - pos) mod 26 ---")
best_const = (0, 0)
for KEY in range(26):
    matches = sum(1 for i, pos in enumerate(sorted_positions)
                  if (KEY - pos) % 26 == beau_values[i])
    if matches > best_const[0]:
        best_const = (matches, KEY)
print(f"  Best: {best_const[0]}/24 at KEY={best_const[1]} ({N2L[best_const[1]]})")

# k[i] = (KEYWORD[i%L] - i) mod 26
print(f"\n--- 8b. k = (KEYWORD[pos%L] - pos) mod 26 ---")
for kw_name, kw_vals in KEYWORDS.items():
    L = len(kw_vals)
    for shift in range(L):
        matches = sum(1 for i, pos in enumerate(sorted_positions)
                      if (kw_vals[(pos + shift) % L] - pos) % 26 == beau_values[i])
        if matches >= 5:
            print(f"  {kw_name} shift={shift}: {matches}/24")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SECTION 9: VIGENERE KEYSTREAM ANALYSIS")
print("=" * 80)

print(f"\nVigenere keystream at crib positions:")
print(f"{'Pos':>4} {'Vig_K':>7} {'Letter':>7}")
for pos in sorted_positions:
    vk = vig_keystream[pos]
    print(f"{pos:>4} {vk:>7} {N2L[vk]:>7}")

vig_values_list = [vig_keystream[p] for p in sorted_positions]
vig_letters = ''.join(N2L[v] for v in vig_values_list)
print(f"\nVig keystream letters: {vig_letters}")

# Check Vigenere keystream for periodic structure
print(f"\n--- Vig keystream periodicity ---")
for p in range(1, 20):
    residue_map = {}
    conflicts = 0
    for pos in sorted_positions:
        r = pos % p
        if r in residue_map:
            if residue_map[r] != vig_keystream[pos]:
                conflicts += 1
        else:
            residue_map[r] = vig_keystream[pos]
    if conflicts <= 2:
        print(f"  period {p}: {conflicts} conflicts")

# Check Vig keystream against DEFECTOR
print(f"\n--- Vig DEFECTOR periodic check ---")
kw_def = KEYWORDS['DEFECTOR']
for shift in range(8):
    matches = sum(1 for i, pos in enumerate(sorted_positions)
                  if kw_def[(pos + shift) % 8] == vig_values_list[i])
    if matches >= 3:
        print(f"  DEFECTOR shift={shift}: {matches}/24")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SECTION 10: BEAN CONSTRAINT VERIFICATION")
print("=" * 80)

# Bean: k[27] = k[65] in CT97 space
# After null removal and col7, where do positions 27 and 65 map?
print(f"\nBean equality: k[27] = k[65] in CT97 space")
for bean_pos in [27, 65]:
    if bean_pos in MASK_SET:
        print(f"  CT97 pos {bean_pos}: IN NULL MASK (removed)")
    elif bean_pos in ct97_to_ct73:
        pos73 = ct97_to_ct73[bean_pos]
        if pos73 in ct73_to_inter:
            pos_inter = ct73_to_inter[pos73]
            print(f"  CT97 pos {bean_pos} -> CT73 pos {pos73} -> Inter pos {pos_inter}")
            if pos_inter in beau_keystream:
                print(f"    Beaufort key = {beau_keystream[pos_inter]} ({N2L[beau_keystream[pos_inter]]})")
            else:
                print(f"    (Not a crib position in intermediate space)")
        else:
            print(f"  CT97 pos {bean_pos} -> CT73 pos {pos73} -> no inter mapping")

# Check Bean on the DEFECTOR autokey model
print(f"\nBean equality on DEFECTOR autokey model:")
for bean_pos in [27, 65]:
    if bean_pos in ct97_to_ct73:
        pos73 = ct97_to_ct73[bean_pos]
        if pos73 in ct73_to_inter:
            pos_inter = ct73_to_inter[pos73]
            dk = defector_key[pos_inter]
            print(f"  CT97 pos {bean_pos} -> inter pos {pos_inter}: DEFECTOR key = {dk} ({N2L[dk]})")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SECTION 11: ADDITIONAL DEEP ANALYSIS")
print("=" * 80)

# 11a. What if the key is CT-autokey (key[i] = CT_intermediate[i-L])?
print(f"\n--- 11a. CT-autokey check: key[i] = INTER[i-L] ---")
for L in range(1, 20):
    matches = 0
    total = 0
    for pos in sorted_positions:
        if pos - L >= 0:
            total += 1
            if I2N[INTER[pos - L]] == beau_keystream[pos]:
                matches += 1
    if total > 0 and matches >= 3:
        print(f"  L={L}: {matches}/{total} matches")

# 11b. What if the key is generated by a different autokey with different primer?
print(f"\n--- 11b. Autokey with various primers (check score at crib positions) ---")
best_primers = []
for primer_len in range(3, 13):
    # For each possible primer, simulate Beaufort PT-autokey and score
    # This is too expensive for all 26^L, so check only known keywords
    for kw_name in ['KRYPTOS', 'DEFECTOR', 'ABSCISSA', 'PALIMPSEST', 'KOMPASS',
                     'COLOPHON', 'PARALLAX', 'BERLIN', 'CLOCK', 'BERLINCLOCK']:
        kw_text = kw_name
        if len(kw_text) != primer_len:
            continue
        primer = [I2N[c] for c in kw_text]

        # Simulate Beaufort PT-autokey
        pt_sim = []
        key_sim = []
        for i in range(73):
            if i < len(primer):
                k = primer[i]
            else:
                k = pt_sim[i - len(primer)]
            key_sim.append(k)
            pt_val = (k - inter_nums[i]) % 26
            pt_sim.append(pt_val)

        # Score at crib positions
        score = 0
        for pos in sorted_positions:
            if key_sim[pos] == beau_keystream[pos]:
                score += 1

        if score >= 10:
            best_primers.append((score, kw_name, 'AZ_beau_pt_autokey'))

        # Also try CT-autokey: key[i] = CT_inter[i-L] for i >= L
        key_ct = []
        pt_ct = []
        for i in range(73):
            if i < len(primer):
                k = primer[i]
            else:
                k = inter_nums[i - len(primer)]
            key_ct.append(k)
            pt_val = (k - inter_nums[i]) % 26
            pt_ct.append(pt_val)

        score_ct = 0
        for pos in sorted_positions:
            if key_ct[pos] == beau_keystream[pos]:
                score_ct += 1

        if score_ct >= 10:
            best_primers.append((score_ct, kw_name, 'AZ_beau_ct_autokey'))

        # Vigenere autokey variants
        # PT-autokey: key[i] = PT[i-L], PT = C - K mod 26 (vig decrypt)
        pt_vig = []
        key_vig = []
        for i in range(73):
            if i < len(primer):
                k = primer[i]
            else:
                k = pt_vig[i - len(primer)]
            key_vig.append(k)
            pt_val = (inter_nums[i] - k) % 26
            pt_vig.append(pt_val)

        score_vig = 0
        for pos in sorted_positions:
            # Vig keystream = (C - P) mod 26
            expected_vig_k = (inter_nums[pos] - I2N[crib_inter_positions[pos][1]]) % 26
            if key_vig[pos] == expected_vig_k:
                score_vig += 1

        if score_vig >= 10:
            best_primers.append((score_vig, kw_name, 'AZ_vig_pt_autokey'))

best_primers.sort(reverse=True)
print(f"\n  Primers scoring ≥10/24:")
for score, name, mode in best_primers[:15]:
    print(f"    {name}:{mode} -> {score}/24")

# 11c. Keystream as XOR of two known sequences
print(f"\n--- 11c. Keystream = keyword XOR running-key ---")
# Check if beau_k[i] = DEFECTOR[(i+s1)%8] XOR something_simple[(i+s2)%L2]
for kw2_name, kw2_vals in KEYWORDS.items():
    L2 = len(kw2_vals)
    for s1 in range(8):
        for s2 in range(L2):
            matches = 0
            for i, pos in enumerate(sorted_positions):
                combined = kw_def[(pos + s1) % 8] ^ kw2_vals[(pos + s2) % L2]
                if combined % 26 == beau_values[i]:
                    matches += 1
            if matches >= 8:
                print(f"  DEFECTOR(s={s1}) XOR {kw2_name}(s={s2}): {matches}/24")

# 11d. Analysis of match/miss pattern relative to position in intermediate
print(f"\n--- 11d. Match/miss pattern in intermediate space ---")
match_set = set(match_positions)
miss_set = set(miss_positions)
print(f"  Match positions (sorted): {sorted(match_set)}")
print(f"  Miss positions  (sorted): {sorted(miss_set)}")

# Grid visualization (width 7)
print(f"\n  Grid visualization (width 7, M=match, X=miss, .=non-crib):")
for r in range(nrows):
    row_str = ""
    for c in range(W):
        pos = r * W + c
        if pos >= 73:
            row_str += " "
        elif pos in match_set:
            row_str += "M"
        elif pos in miss_set:
            row_str += "X"
        else:
            row_str += "."
    print(f"    row {r:>2}: {row_str}")

# Check if misses correlate with grid column
miss_cols = Counter([p % W for p in miss_set])
match_cols = Counter([p % W for p in match_set])
print(f"\n  Miss by column: {dict(miss_cols)}")
print(f"  Match by column: {dict(match_cols)}")

# Check if misses correlate with grid row
miss_rows = Counter([p // W for p in miss_set])
match_rows = Counter([p // W for p in match_set])
print(f"  Miss by row: {dict(miss_rows)}")
print(f"  Match by row: {dict(match_rows)}")

# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"\nBeau keystream: {''.join(N2L[beau_keystream[p]] for p in sorted_positions)}")
print(f"Vig  keystream: {''.join(N2L[vig_keystream[p]] for p in sorted_positions)}")
print(f"IC (Beau): {ic:.4f}")
print(f"DEFECTOR autokey matches: {match_count}/24")
if deltas:
    print(f"Correction vector: {delta_vals} = {''.join(delta_letters)}")
    print(f"Delta distinct values: {len(set(delta_vals))}")

# Save results
os.makedirs("/home/cpatrick/kryptos/results", exist_ok=True)
results = {
    'experiment': 'E-KEYSTREAM-FORENSICS',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    'mask': MASK,
    'ct73': CT73,
    'intermediate': INTER,
    'beaufort_keystream': {str(p): {'value': beau_keystream[p], 'letter': N2L[beau_keystream[p]]}
                           for p in sorted_positions},
    'vigenere_keystream': {str(p): {'value': vig_keystream[p], 'letter': N2L[vig_keystream[p]]}
                           for p in sorted_positions},
    'ic_beaufort': ic,
    'defector_matches': match_count,
    'defector_match_positions': match_positions,
    'defector_miss_positions': miss_positions,
    'correction_vector': delta_vals,
    'correction_letters': ''.join(delta_letters),
}

outpath = "/home/cpatrick/kryptos/results/e_keystream_forensics.json"
with open(outpath, "w") as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nArtifact: {outpath}")
print(f"Repro: PYTHONPATH=src python3 -u scripts/analysis/e_keystream_forensics.py")
