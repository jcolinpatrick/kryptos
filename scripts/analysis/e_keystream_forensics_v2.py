#!/usr/bin/env python3
"""
Cipher: Beaufort (analysis)
Family: analysis
Status: active
Keyspace: N/A (analytical)
Last run: 2026-03-15
Best score: N/A
"""
"""E-KEYSTREAM-FORENSICS-V2: Corrected deep analysis of the 24 Beaufort keystream values.

CRITICAL BUG FIX from v1: Crib positions in intermediate space are NOT obtained by
mapping CT97 positions through null-mask and col7. They are simply:
  ENE at positions ENE_S..ENE_S+12 (where ENE_S = 21 - nulls_before_21 = 13)
  BCL at positions BCL_S..BCL_S+10 (where BCL_S = 63 - nulls_before_63 = 47)
because the model is: CT73 -> col7 -> intermediate -> Beaufort_autokey -> PT,
and PT positions = intermediate positions.

Analyses:
  1. Basic properties (freqs, IC, palette)
  2. Periodicity (0-conflict periods)
  3. Recurrence relations (Gromark/Fibonacci)
  4. Running key patterns (K1-K3 PT, keywords)
  5. Position-dependent key functions
  6. DEFECTOR autokey comparison (15/24 match identification)
  7. Correction vector analysis (the 9 mismatches)
  8. Beaufort encryption of position
  9. Vigenere keystream comparison
 10. Bean constraint verification
"""

import json, os, time
from collections import Counter
from itertools import product

# -- Constants ---------------------------------------------------------------
CT97 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
N2L = {i: c for i, c in enumerate(AZ)}

# Consensus null mask (24 positions)
MASK = [0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 39, 40, 52, 55, 58, 59, 74, 75, 78, 84, 85, 88, 94, 96]
MASK_SET = frozenset(MASK)
assert len(MASK) == 24

# Cribs (0-indexed in CT97 space)
ENE_START_97 = 21
ENE_TEXT = "EASTNORTHEAST"
BCL_START_97 = 63
BCL_TEXT = "BERLINCLOCK"

ENE_NUMS = [I2N[c] for c in ENE_TEXT]
BCL_NUMS = [I2N[c] for c in BCL_TEXT]

# Thematic keywords
KEYWORDS = {
    'KRYPTOS': [I2N[c] for c in 'KRYPTOS'],
    'DEFECTOR': [I2N[c] for c in 'DEFECTOR'],
    'ABSCISSA': [I2N[c] for c in 'ABSCISSA'],
    'PALIMPSEST': [I2N[c] for c in 'PALIMPSEST'],
    'SEVEN': [I2N[c] for c in 'SEVEN'],
    'KOMPASS': [I2N[c] for c in 'KOMPASS'],
    'COLOPHON': [I2N[c] for c in 'COLOPHON'],
    'PARALLAX': [I2N[c] for c in 'PARALLAX'],
    'BERLIN': [I2N[c] for c in 'BERLIN'],
    'CLOCK': [I2N[c] for c in 'CLOCK'],
    'BERLINCLOCK': [I2N[c] for c in 'BERLINCLOCK'],
}

# K1-K3 plaintexts
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"

# KA alphabet
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_I2N = {c: i for i, c in enumerate(KA)}

PALETTE = set('BGIKOWZ')

# -- Step 1: Extract 73 chars (remove 24 nulls) ----------------------------
CT73_RAW = [ord(CT97[i]) - 65 for i in range(97) if i not in MASK_SET]
CT73_STR = ''.join(chr(c + 65) for c in CT73_RAW)
assert len(CT73_RAW) == 73

# Null counts before crib starts
n1 = sum(1 for p in MASK if p < ENE_START_97)  # 8
n2 = sum(1 for p in MASK if p < BCL_START_97)  # 16

# Crib positions in CT73 space (= PT space before transposition)
ENE_S = ENE_START_97 - n1  # 13
BCL_S = BCL_START_97 - n2  # 47

# -- Step 2: Apply col7 transposition (inverse columnar) -------------------
def columnar_perm(n, width):
    """Forward columnar transposition: write by rows, read by columns."""
    grid = []
    for row in range((n + width - 1) // width):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(len(grid)):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = reverse_perm(columnar_perm(73, 7))

# Apply: intermediate[i] = CT73[PERM_COL7[i]] (undo columnar transposition)
INTER = [CT73_RAW[PERM_COL7[i]] for i in range(73)]
INTER_STR = ''.join(chr(c + 65) for c in INTER)

print("=" * 80)
print("E-KEYSTREAM-FORENSICS-V2: Corrected Beaufort Keystream Deep Analysis")
print("=" * 80)
print(f"\nCT97:         {CT97}")
print(f"CT73:         {CT73_STR}")
print(f"Intermediate: {INTER_STR}")
print(f"Nulls:        {sorted(MASK)}")
print(f"\nCrib positions in PT/intermediate space:")
print(f"  ENE: positions {ENE_S}..{ENE_S+12} (n1={n1} nulls before CT97 pos {ENE_START_97})")
print(f"  BCL: positions {BCL_S}..{BCL_S+10} (n2={n2} nulls before CT97 pos {BCL_START_97})")

# Verify intermediate is correct by running DEFECTOR autokey
DEFECTOR_AZ = [I2N[c] for c in "DEFECTOR"]

def autokey_pt_beau(ct_nums, primer, offset):
    n = len(ct_nums)
    L = len(primer)
    pt = [0] * n
    for i in range(n):
        if i < L:
            k = primer[i]
        else:
            fb_idx = i - offset
            k = pt[fb_idx] if fb_idx >= 0 else primer[i % L]
        pt[i] = (k - ct_nums[i]) % 26
    return pt

pt_defector = autokey_pt_beau(INTER, DEFECTOR_AZ, 8)
ene_match = sum(1 for j in range(13) if pt_defector[ENE_S + j] == ENE_NUMS[j])
bcl_match = sum(1 for j in range(11) if pt_defector[BCL_S + j] == BCL_NUMS[j])
print(f"\nDEFECTOR:AZ_beau+col7 verification: {ene_match+bcl_match}/24 (ene={ene_match}/13, bcl={bcl_match}/11)")
assert ene_match + bcl_match == 15, f"Expected 15/24, got {ene_match+bcl_match}"
print("  VERIFIED: 15/24")

# -- Step 3: Compute the CORRECT Beaufort keystream at crib positions ------
# At crib positions, we KNOW the plaintext.
# The model decrypts: PT[i] = (K[i] - INTER[i]) mod 26
# Therefore: K[i] = (PT[i] + INTER[i]) mod 26
# This is the Beaufort keystream = (CT_intermediate + PT_correct) mod 26

print("\n" + "=" * 80)
print("SECTION 1: BASIC PROPERTIES")
print("=" * 80)

# Build the 24 crib entries: (intermediate_pos, CT_inter_val, PT_correct_val)
crib_entries = []  # (pos, ct_val, pt_val)
for j in range(13):
    p = ENE_S + j
    crib_entries.append((p, INTER[p], ENE_NUMS[j]))
for j in range(11):
    p = BCL_S + j
    crib_entries.append((p, INTER[p], BCL_NUMS[j]))

crib_entries.sort(key=lambda x: x[0])

beau_keystream = {}  # pos -> key_value
vig_keystream = {}
for pos, ct_val, pt_val in crib_entries:
    beau_keystream[pos] = (ct_val + pt_val) % 26
    vig_keystream[pos] = (ct_val - pt_val) % 26

sorted_positions = sorted(beau_keystream.keys())
beau_values = [beau_keystream[p] for p in sorted_positions]
vig_values = [vig_keystream[p] for p in sorted_positions]

# Also compute the DEFECTOR autokey key at these positions
defector_key = [0] * 73
for i in range(73):
    if i < 8:
        defector_key[i] = DEFECTOR_AZ[i]
    else:
        defector_key[i] = pt_defector[i - 8]

print(f"\n--- 1a. All 24 (position, keystream_value) pairs ---")
print(f"{'Pos':>4} {'Beau_K':>7} {'BLet':>5} {'Vig_K':>7} {'VLet':>5} {'CT_i':>5} {'PT':>4} {'DEF_K':>6} {'DEFl':>5} {'=?':>3}")
for pos, ct_val, pt_val in crib_entries:
    bk = beau_keystream[pos]
    vk = vig_keystream[pos]
    dk = defector_key[pos]
    match = "YES" if bk == dk else "no"
    print(f"{pos:>4} {bk:>7} {N2L[bk]:>5} {vk:>7} {N2L[vk]:>5} {N2L[ct_val]:>5} {N2L[pt_val]:>4} {dk:>6} {N2L[dk]:>5} {match:>3}")

beau_letters_str = ''.join(N2L[beau_keystream[p]] for p in sorted_positions)
vig_letters_str = ''.join(N2L[vig_keystream[p]] for p in sorted_positions)
print(f"\nBeau keystream letters: {beau_letters_str}")
print(f"Vig  keystream letters: {vig_letters_str}")

# Frequency analysis
beau_freq = Counter(beau_values)
print(f"\n--- 1b. Letter frequencies (Beaufort keystream) ---")
for val, count in sorted(beau_freq.items()):
    print(f"  {N2L[val]}({val:>2}): {'#' * count} {count}")

# IC
n_ks = len(beau_values)
ic_num = sum(c * (c - 1) for c in beau_freq.values())
ic_den = n_ks * (n_ks - 1)
ic = ic_num / ic_den if ic_den > 0 else 0
print(f"\n--- 1c. IC of 24-value Beaufort keystream: {ic:.4f} ---")
print(f"  Random IC (26 letters): {1/26:.4f}")
print(f"  English IC: 0.0667")
print(f"  {'ABOVE' if ic > 1/26 else 'BELOW'} random expectation ({ic/(1/26):.2f}x random)")

# Palette
palette_count = sum(1 for v in beau_values if N2L[v] in PALETTE)
print(f"\n--- 1d. Palette letters {{B,G,I,K,O,W,Z}} count: {palette_count}/24 ---")
for pos in sorted_positions:
    bk = beau_keystream[pos]
    letter = N2L[bk]
    flag = " <-- PALETTE" if letter in PALETTE else ""
    print(f"  pos {pos:>2}: {letter}{flag}")

# =========================================================================
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
        status = "*** 0 CONFLICTS ***" if conflicts == 0 else f"{conflicts} conflicts"
        if conflicts <= 3:
            print(f"  period {p:>2}: {status} ({n_residues} residues used)")

# =========================================================================
print("\n" + "=" * 80)
print("SECTION 3: RECURRENCE RELATIONS")
print("=" * 80)

print(f"\nENE positions (intermediate): {[ENE_S+j for j in range(13)]}")
print(f"BCL positions (intermediate): {[BCL_S+j for j in range(11)]}")
print(f"NOTE: positions are NOT contiguous -- ENE = 13..25, BCL = 47..57")
print(f"      gap of {BCL_S - (ENE_S+12) - 1} positions between ENE end and BCL start")

# Check recurrence on the 24 known keystream values
# Since positions have a large gap, only same-crib checks will have both sources available
print("\n--- Addition recurrence: k[i] = (k[i-a] + k[i-b]) mod M ---")
best_recurrences = []
for M in [5, 7, 8, 10, 13, 26]:
    for a in range(1, 30):
        for b in range(a + 1, 30):
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
            if total_checkable >= 3 and matches >= total_checkable - 1 and matches >= 3:
                best_recurrences.append((matches, total_checkable, a, b, M, 'add'))

# Subtraction
for M in [5, 7, 8, 10, 13, 26]:
    for a in range(1, 30):
        for b in range(1, 30):
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
            if total_checkable >= 3 and matches >= total_checkable - 1 and matches >= 3:
                best_recurrences.append((matches, total_checkable, a, b, M, 'sub'))

best_recurrences.sort(key=lambda x: (-x[0], x[1]))
print(f"  Perfect or near-perfect recurrences (<=1 miss, >=3 checkable):")
for matches, total, a, b, M, op in best_recurrences[:20]:
    pct = matches / total * 100 if total > 0 else 0
    print(f"    k[i]=(k[i-{a}]{'+' if op=='add' else '-'}k[i-{b}])%{M}: {matches}/{total} ({pct:.0f}%)")

if not best_recurrences:
    print("  NONE found with >=3 checkable and <=1 miss")

# Standard Gromark
print("\n--- Standard Gromark check: k[i] = (k[i-5] + k[i-4]) mod 10 ---")
gm_matches = 0
gm_total = 0
for pos in sorted_positions:
    if pos - 5 in beau_keystream and pos - 4 in beau_keystream:
        gm_total += 1
        predicted = (beau_keystream[pos - 5] + beau_keystream[pos - 4]) % 10
        actual = beau_keystream[pos] % 10
        match_str = "MATCH" if predicted == actual else "miss"
        print(f"    pos {pos}: k[{pos-5}]={beau_keystream[pos-5]}+k[{pos-4}]={beau_keystream[pos-4]}"
              f"={(beau_keystream[pos-5]+beau_keystream[pos-4])%10}%10, actual={actual} [{match_str}]")
        if predicted == actual:
            gm_matches += 1
print(f"  Gromark: {gm_matches}/{gm_total}")

# =========================================================================
print("\n" + "=" * 80)
print("SECTION 4: RUNNING KEY PATTERNS")
print("=" * 80)

def check_running_key(ks_values, ks_positions, source_text, source_name):
    source_nums = [I2N[c] for c in source_text]
    best_offset = -1
    best_matches = 0
    for offset in range(-max(ks_positions) - len(source_text), len(source_text) + max(ks_positions)):
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

print("\n--- 4a. K1/K2/K3 PT as running key (Beaufort keystream) ---")
for name, text in [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT)]:
    offset, matches = check_running_key(beau_values, sorted_positions, text, name)
    print(f"  {name}: best {matches}/24 at offset {offset}")

K123 = K1_PT + K2_PT + K3_PT
offset, matches = check_running_key(beau_values, sorted_positions, K123, "K1+K2+K3")
print(f"  K1+K2+K3: best {matches}/24 at offset {offset}")

# Also try Vigenere keystream
print("\n--- 4a'. K1/K2/K3 PT as running key (Vigenere keystream) ---")
for name, text in [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT)]:
    offset, matches = check_running_key(vig_values, sorted_positions, text, name)
    print(f"  {name}: best {matches}/24 at offset {offset}")

print("\n--- 4b. Cyclic keyword matches (Beaufort) ---")
for kw_name, kw_vals in KEYWORDS.items():
    L = len(kw_vals)
    best_m = 0
    best_shift = 0
    for shift in range(L):
        matches = sum(1 for i, pos in enumerate(sorted_positions) if kw_vals[(pos + shift) % L] == beau_values[i])
        if matches > best_m:
            best_m = matches
            best_shift = shift
    if best_m >= 3:
        print(f"  {kw_name:>15} (L={L}): best {best_m}/24 at shift {best_shift}")

# =========================================================================
print("\n" + "=" * 80)
print("SECTION 5: POSITION-DEPENDENT KEY")
print("=" * 80)

# k = (a*pos + b) mod 26
print("\n--- 5a. Linear: k = (a*pos + b) mod 26 ---")
best_linear = (0, 0, 0)
for a in range(26):
    for b in range(26):
        matches = sum(1 for i, pos in enumerate(sorted_positions) if (a * pos + b) % 26 == beau_values[i])
        if matches > best_linear[0]:
            best_linear = (matches, a, b)
print(f"  Best: {best_linear[0]}/24 at a={best_linear[1]}, b={best_linear[2]}")

# k = (a*pos^2 + b*pos + c) mod 26
print("\n--- 5b. Quadratic: k = (a*pos^2 + b*pos + c) mod 26 ---")
best_quad = (0, 0, 0, 0)
for a in range(26):
    for b in range(26):
        pos0 = sorted_positions[0]
        c_val = (beau_values[0] - a * pos0 * pos0 - b * pos0) % 26
        matches = sum(1 for i, pos in enumerate(sorted_positions)
                      if (a * pos * pos + b * pos + c_val) % 26 == beau_values[i])
        if matches > best_quad[0]:
            best_quad = (matches, a, b, c_val)
print(f"  Best: {best_quad[0]}/24 at a={best_quad[1]}, b={best_quad[2]}, c={best_quad[3]}")

# DEFECTOR[pos%8] periodic
print("\n--- 5c. DEFECTOR[pos%8] (periodic) ---")
kw_def = KEYWORDS['DEFECTOR']
for shift in range(8):
    matches = 0
    for i, pos in enumerate(sorted_positions):
        if kw_def[(pos + shift) % 8] == beau_values[i]:
            matches += 1
    if matches >= 3:
        print(f"  shift={shift}: {matches}/24")

# Combined keyword functions
print("\n--- 5d. Combined: (KRYPTOS[pos%7] op SEVEN[pos%5]) mod 26 ---")
kw_k = KEYWORDS['KRYPTOS']
kw_s = KEYWORDS['SEVEN']
for op_name, op in [("add", lambda a, b: (a + b) % 26),
                     ("sub_ks", lambda a, b: (a - b) % 26),
                     ("sub_sk", lambda a, b: (b - a) % 26),
                     ("beau_ks", lambda a, b: (a + b) % 26)]:  # Beaufort = add for key
    best_m = 0
    best_params = (0, 0)
    for sk in range(7):
        for ss in range(5):
            matches = sum(1 for i, pos in enumerate(sorted_positions)
                          if op(kw_k[(pos + sk) % 7], kw_s[(pos + ss) % 5]) == beau_values[i])
            if matches > best_m:
                best_m = matches
                best_params = (sk, ss)
    print(f"  KRYPTOS {op_name} SEVEN: best {best_m}/24 (sk={best_params[0]}, ss={best_params[1]})")

# =========================================================================
print("\n" + "=" * 80)
print("SECTION 6: DEFECTOR AUTOKEY COMPARISON (THE 15 THAT MATCH)")
print("=" * 80)

print(f"\nDEFECTOR:AZ_beau autokey PT: {''.join(chr(65+v) for v in pt_defector)}")

# Compare at each crib position
print(f"\n--- 6a. Per-position comparison ---")
print(f"{'Pos':>4} {'Correct_K':>10} {'Defector_K':>11} {'Match':>6} {'Delta':>6} {'DLet':>5} {'CribPT':>7} {'DefPT':>6} {'PTdelta':>8}")

match_count = 0
match_positions = []
miss_positions = []
deltas = []
all_comparisons = []

for pos, ct_val, pt_correct_val in crib_entries:
    correct_k = beau_keystream[pos]
    dk = defector_key[pos]
    def_pt_val = pt_defector[pos]
    is_match = (correct_k == dk)  # equivalently: pt_correct == pt_defector at this pos
    delta_k = (correct_k - dk) % 26
    pt_delta = (pt_correct_val - def_pt_val) % 26

    comp = {
        'pos': pos,
        'correct_k': correct_k,
        'defector_k': dk,
        'match': is_match,
        'delta_k': delta_k,
        'pt_correct': pt_correct_val,
        'pt_defector': def_pt_val,
        'pt_delta': pt_delta,
    }
    all_comparisons.append(comp)

    if is_match:
        match_count += 1
        match_positions.append(pos)
        status = "YES"
    else:
        miss_positions.append(pos)
        deltas.append((pos, delta_k, pt_delta))
        status = "NO"

    print(f"{pos:>4} {N2L[correct_k]:>6}({correct_k:>2}) {N2L[dk]:>7}({dk:>2}) {status:>6} {delta_k:>6} {N2L[delta_k]:>5} {N2L[pt_correct_val]:>7} {N2L[def_pt_val]:>6} {pt_delta:>4}({N2L[pt_delta]})")

print(f"\nTotal matches: {match_count}/24")
print(f"Match positions: {match_positions}")
print(f"Miss positions:  {[p for p, _, _ in deltas]}")

# Identify which crib each belongs to
print(f"\n--- 6b. Match/miss by crib ---")
ene_matches = [p for p in match_positions if ENE_S <= p <= ENE_S + 12]
ene_misses = [p for p, _, _ in deltas if ENE_S <= p <= ENE_S + 12]
bcl_matches = [p for p in match_positions if BCL_S <= p <= BCL_S + 10]
bcl_misses = [p for p, _, _ in deltas if BCL_S <= p <= BCL_S + 10]
print(f"  ENE: {len(ene_matches)}/13 match, {len(ene_misses)} miss at positions {ene_misses}")
print(f"  BCL: {len(bcl_matches)}/11 match, {len(bcl_misses)} miss at positions {bcl_misses}")
print(f"  ENE match positions: {ene_matches}")
print(f"  BCL match positions: {bcl_matches}")

# Grid visualization
W = 7
nrows = (73 + W - 1) // W  # 11
print(f"\n--- 6c. Grid visualization (width 7, M=match, X=miss, .=non-crib) ---")
for r in range(nrows):
    row_str = ""
    for c in range(W):
        pos = r * W + c
        if pos >= 73:
            row_str += " "
        elif pos in set(match_positions):
            row_str += "M"
        elif pos in set(p for p, _, _ in deltas):
            row_str += "X"
        else:
            row_str += "."
    print(f"    row {r:>2}: {row_str}")

# =========================================================================
print("\n" + "=" * 80)
print("SECTION 7: CORRECTION VECTOR ANALYSIS (THE KEY QUESTION)")
print("=" * 80)

delta_k_vals = [d for _, d, _ in deltas]
delta_pt_vals = [d for _, _, d in deltas]
delta_k_letters = [N2L[d] for d in delta_k_vals]
delta_pt_letters = [N2L[d] for d in delta_pt_vals]

print(f"\n--- 7a. Key-delta: (correct_key - DEFECTOR_key) mod 26 ---")
print(f"  Miss positions: {[p for p, _, _ in deltas]}")
print(f"  Key delta values:   {delta_k_vals}")
print(f"  Key delta letters:  {''.join(delta_k_letters)}")
print(f"  NOTE: For Beaufort, key_delta = PT_delta (since K = CT + PT, delta_K = delta_PT)")

print(f"\n--- 7a'. PT-delta: (correct_PT - DEFECTOR_PT) mod 26 ---")
print(f"  PT delta values:   {delta_pt_vals}")
print(f"  PT delta letters:  {''.join(delta_pt_letters)}")

# Verify key_delta == pt_delta for Beaufort
for (pos, dk, dppt) in deltas:
    assert dk == dppt, f"Key delta {dk} != PT delta {dppt} at pos {pos}"
print(f"  VERIFIED: key_delta == pt_delta at all 9 miss positions (Beaufort property)")

# Is delta constant?
if len(set(delta_k_vals)) == 1:
    print(f"\n  *** CONSTANT DELTA: {delta_k_vals[0]} ({N2L[delta_k_vals[0]]}) ***")
else:
    print(f"\n  Delta is NOT constant ({len(set(delta_k_vals))} distinct values)")
    delta_freq = Counter(delta_k_vals)
    for val, cnt in delta_freq.most_common():
        print(f"    {N2L[val]}({val:>2}): {cnt}x")

# Is delta periodic?
print(f"\n--- 7b. Delta periodicity ---")
for p in range(2, 20):
    residue_map = {}
    conflicts = 0
    for pos, delta, _ in deltas:
        r = pos % p
        if r in residue_map:
            if residue_map[r] != delta:
                conflicts += 1
        else:
            residue_map[r] = delta
    if conflicts == 0:
        print(f"  period {p}: CONSISTENT ({len(residue_map)} residues: {dict(residue_map)})")
    elif conflicts == 1:
        print(f"  period {p}: 1 conflict ({len(residue_map)} residues)")

# Check if delta = known keyword applied cyclically
print(f"\n--- 7c. Delta as cyclic keyword ---")
for kw_name, kw_vals in KEYWORDS.items():
    L = len(kw_vals)
    for shift in range(L):
        matches = sum(1 for pos, delta, _ in deltas if kw_vals[(pos + shift) % L] == delta)
        if matches >= 3:
            print(f"  {kw_name}[({'+' if shift >= 0 else ''}{shift}+pos)%{L}]: {matches}/{len(deltas)} match")

# Check delta = function(position)
print(f"\n--- 7d. Delta as function of miss-position ---")
for a in range(26):
    for b in range(26):
        matches = sum(1 for pos, delta, _ in deltas if (a * pos + b) % 26 == delta)
        if matches >= len(deltas) - 1:
            print(f"  delta = ({a}*pos + {b}) mod 26: {matches}/{len(deltas)} match")

# What does the DEFECTOR model produce at the miss positions?
print(f"\n--- 7e. Detailed miss position analysis ---")
print(f"{'Pos':>4} {'Crib':>5} {'Offset':>7} {'CorrectPT':>10} {'DefPT':>6} {'PTdelta':>8} {'DefKey':>7} {'KeySrc':>50}")
for pos, delta_k, delta_pt in deltas:
    # What crib is this from?
    if ENE_S <= pos <= ENE_S + 12:
        crib_name = "ENE"
        crib_offset = pos - ENE_S
    else:
        crib_name = "BCL"
        crib_offset = pos - BCL_S

    # Where does the DEFECTOR key come from?
    dk = defector_key[pos]
    if pos < 8:
        key_src = f"primer[{pos}]={chr(65+DEFECTOR_AZ[pos])}"
    else:
        fb = pos - 8
        key_src = f"PT[{fb}]={chr(65+pt_defector[fb])}"
        # Is PT[fb] a crib position?
        if ENE_S <= fb <= ENE_S + 12:
            fb_crib = f" (ENE[{fb-ENE_S}]={'OK' if pt_defector[fb]==ENE_NUMS[fb-ENE_S] else 'WRONG'})"
        elif BCL_S <= fb <= BCL_S + 10:
            fb_crib = f" (BCL[{fb-BCL_S}]={'OK' if pt_defector[fb]==BCL_NUMS[fb-BCL_S] else 'WRONG'})"
        else:
            fb_crib = " (non-crib)"
        key_src += fb_crib

    correct_pt = None
    for p, cv, pv in crib_entries:
        if p == pos:
            correct_pt = pv
            break

    print(f"{pos:>4} {crib_name:>5}[{crib_offset:>2}] {N2L[correct_pt]:>10} {N2L[pt_defector[pos]]:>6} {delta_pt:>4}({N2L[delta_pt]}) {dk:>3}({N2L[dk]}) {key_src}")

# =========================================================================
print("\n" + "=" * 80)
print("SECTION 7F: ERROR PROPAGATION ANALYSIS")
print("=" * 80)
print("\nThe DEFECTOR autokey model has 15/24 matches. The 9 misses occur because")
print("the autokey feedback chain passes through non-crib positions where we do NOT")
print("know the correct plaintext. Any wrong PT value propagates forward as a wrong key.")
print()

# Trace the error chain
print("Error propagation chain:")
print("For each miss position p, key[p] = PT[p-8] (autokey feedback offset=8)")
print("If p-8 is a non-crib position, we can't know PT[p-8] is correct.")
print()

# Check: at each miss position, is the feedback source (p-8) a crib position?
crib_positions_set = set(sorted_positions)
for pos, delta_k, delta_pt in deltas:
    fb_pos = pos - 8
    fb_is_crib = fb_pos in crib_positions_set
    if fb_is_crib:
        fb_matches_crib = beau_keystream[fb_pos] == defector_key[fb_pos]
        status = f"IS crib, key match={fb_matches_crib}"
    else:
        status = "NOT crib (unknown PT)"
    print(f"  miss@{pos}: key=PT[{fb_pos}] -> {status}")

# How many miss positions feed from non-crib?
non_crib_fb = sum(1 for pos, _, _ in deltas if pos - 8 not in crib_positions_set)
crib_fb_match = sum(1 for pos, _, _ in deltas if pos - 8 in crib_positions_set and beau_keystream[pos-8] == defector_key[pos-8])
crib_fb_miss = sum(1 for pos, _, _ in deltas if pos - 8 in crib_positions_set and beau_keystream[pos-8] != defector_key[pos-8])
print(f"\n  Summary: {non_crib_fb} miss positions feed from non-crib, {crib_fb_match} from correct crib, {crib_fb_miss} from wrong crib")

# =========================================================================
print("\n" + "=" * 80)
print("SECTION 8: BEAUFORT ENCRYPTION OF POSITION")
print("=" * 80)

# k[i] = (KEY - i) mod 26
print(f"\n--- 8a. k = (KEY - pos) mod 26 ---")
best_const = (0, 0)
for KEY in range(26):
    matches = sum(1 for i, pos in enumerate(sorted_positions) if (KEY - pos) % 26 == beau_values[i])
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
        if matches >= 4:
            print(f"  {kw_name} shift={shift}: {matches}/24")

# =========================================================================
print("\n" + "=" * 80)
print("SECTION 9: VIGENERE KEYSTREAM ANALYSIS")
print("=" * 80)

vig_letters_str = ''.join(N2L[vig_keystream[p]] for p in sorted_positions)
print(f"\nVig keystream letters: {vig_letters_str}")

# Period consistency for Vigenere
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
    if conflicts <= 3:
        print(f"  period {p}: {conflicts} conflicts")

# Vigenere DEFECTOR periodic
print(f"\n--- Vig DEFECTOR periodic check ---")
kw_def = KEYWORDS['DEFECTOR']
for shift in range(8):
    matches = sum(1 for i, pos in enumerate(sorted_positions) if kw_def[(pos + shift) % 8] == vig_values[i])
    if matches >= 3:
        print(f"  DEFECTOR shift={shift}: {matches}/24")

# =========================================================================
print("\n" + "=" * 80)
print("SECTION 10: BEAN CONSTRAINT VERIFICATION")
print("=" * 80)

# Bean: k[27] = k[65] in CT97 space
# After null removal: 27 -> 27 - n_nulls_before_27, 65 -> 65 - n_nulls_before_65
n_before_27 = sum(1 for p in MASK if p < 27)
n_before_65 = sum(1 for p in MASK if p < 65)
pos73_27 = 27 - n_before_27
pos73_65 = 65 - n_before_65
print(f"\nBean positions: CT97[27] -> CT73[{pos73_27}], CT97[65] -> CT73[{pos73_65}]")

# After col7 transposition:
# In intermediate space, position p corresponds to CT73 position PERM_COL7[p]
# We need: which intermediate position has CT73 position pos73_27?
# inter_pos such that PERM_COL7[inter_pos] = pos73_27
# That's the forward perm: fwd = columnar_perm(73, 7); inter_pos = fwd[pos73_27]? No.
# PERM_COL7 = reverse_perm(columnar_perm(73, 7))
# INTER[i] = CT73[PERM_COL7[i]]
# So CT73 position pos73 maps to intermediate position i where PERM_COL7[i] = pos73
# That's: i = FWD_COL7[pos73] where FWD_COL7 = columnar_perm(73, 7)? No.
# reverse_perm(columnar_perm) maps forward to inverse.
# Let's just compute: for each inter pos, what CT73 pos it came from
ct73_to_inter = {}
for i in range(73):
    ct73_to_inter[PERM_COL7[i]] = i

inter_27 = ct73_to_inter.get(pos73_27)
inter_65 = ct73_to_inter.get(pos73_65)
print(f"In intermediate space: CT97[27] -> inter[{inter_27}], CT97[65] -> inter[{inter_65}]")

# Are these crib positions?
if inter_27 in beau_keystream:
    print(f"  inter[{inter_27}] IS a crib position: Beau key = {beau_keystream[inter_27]} ({N2L[beau_keystream[inter_27]]})")
else:
    print(f"  inter[{inter_27}] is NOT a crib position")

if inter_65 in beau_keystream:
    print(f"  inter[{inter_65}] IS a crib position: Beau key = {beau_keystream[inter_65]} ({N2L[beau_keystream[inter_65]]})")
else:
    print(f"  inter[{inter_65}] is NOT a crib position")

if inter_27 in beau_keystream and inter_65 in beau_keystream:
    if beau_keystream[inter_27] == beau_keystream[inter_65]:
        print(f"\n  *** BEAN EQUALITY SATISFIED: k[{inter_27}] = k[{inter_65}] = {beau_keystream[inter_27]} ({N2L[beau_keystream[inter_27]]}) ***")
    else:
        print(f"\n  *** BEAN EQUALITY VIOLATED: k[{inter_27}]={beau_keystream[inter_27]} != k[{inter_65}]={beau_keystream[inter_65]} ***")

# DEFECTOR autokey Bean check
print(f"\nDEFECTOR autokey Bean check:")
print(f"  DEFECTOR key at inter[{inter_27}] = {defector_key[inter_27]} ({N2L[defector_key[inter_27]]})")
print(f"  DEFECTOR key at inter[{inter_65}] = {defector_key[inter_65]} ({N2L[defector_key[inter_65]]})")
if defector_key[inter_27] == defector_key[inter_65]:
    print(f"  DEFECTOR BEAN: SATISFIED")
else:
    print(f"  DEFECTOR BEAN: VIOLATED (delta = {(defector_key[inter_27] - defector_key[inter_65]) % 26})")

# =========================================================================
print("\n" + "=" * 80)
print("SECTION 11: FULL KEYSTREAM STRUCTURE ANALYSIS")
print("=" * 80)

# 11a. At non-crib positions, what key WOULD make the PT correct assuming Beaufort?
# We only know PT at crib positions. But we know the DEFECTOR model's full PT.
# The DEFECTOR PT = the correct PT at 15 positions. At the other 9, it's wrong.
# The correct keystream at the 15 matching positions IS the DEFECTOR key.
# At the 9 miss positions, the correct keystream differs from DEFECTOR key.

print(f"\n--- 11a. Full 73-position key comparison (DEFECTOR vs correct at cribs) ---")
print(f"  DEFECTOR key (73 chars): {''.join(N2L[defector_key[i]] for i in range(73))}")
print(f"  Correct key (at 24 crib positions only):")

full_key_display = []
for i in range(73):
    if i in beau_keystream:
        full_key_display.append(N2L[beau_keystream[i]])
    else:
        full_key_display.append('.')
print(f"  {''.join(full_key_display)}")

# 11b. At the 15 match positions, verify DEFECTOR key = correct key
print(f"\n--- 11b. At 15 match positions, DEFECTOR key gives correct PT ---")
print(f"  This means: the autokey chain produces correct plaintext at these positions.")
print(f"  At the 9 misses, the chain was corrupted by wrong PT at intermediate non-crib positions.")

# 11c. Could a DIFFERENT key generation rule match all 24?
# The correct key at all 24 positions:
print(f"\n--- 11c. What key generation rule produces all 24 correct values? ---")
print(f"  The 24 correct key values (by position):")
for pos in sorted_positions:
    k = beau_keystream[pos]
    # What is INTER[pos-8]?
    if pos >= 8:
        fb_val = INTER[pos - 8]
        fb_char = N2L[fb_val]
    else:
        fb_val = None
        fb_char = '-'
    print(f"    pos {pos:>2}: key={N2L[k]}({k:>2}), INTER[{pos-8:>2}]={fb_char}({fb_val if fb_val is not None else '-':>3}), "
          f"key-INTER={(k - fb_val) % 26 if fb_val is not None else '-':>3}")

# 11d. What if key = some_function(CT_intermediate)?
print(f"\n--- 11d. Key as function of CT intermediate ---")
# Check key[i] = (a * INTER[i] + b) mod 26 (affine of CT)
best_affine = (0, 0, 0)
for a in range(26):
    for b in range(26):
        matches = sum(1 for pos in sorted_positions if (a * INTER[pos] + b) % 26 == beau_keystream[pos])
        if matches > best_affine[0]:
            best_affine = (matches, a, b)
print(f"  Best affine of CT: {best_affine[0]}/24 at a={best_affine[1]}, b={best_affine[2]}")

# Check key[i] = INTER[i+d] for various offsets d
print(f"\n--- 11e. Key = INTER[pos+d] (CT-offset key) ---")
for d in range(-30, 31):
    matches = 0
    for pos in sorted_positions:
        src = pos + d
        if 0 <= src < 73:
            if INTER[src] == beau_keystream[pos]:
                matches += 1
    if matches >= 4:
        print(f"  d={d}: {matches}/24 matches")

# =========================================================================
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"\nBeau keystream: {beau_letters_str}")
print(f"Vig  keystream: {vig_letters_str}")
print(f"IC (Beau):      {ic:.4f} ({ic/(1/26):.2f}x random)")
print(f"Distinct Beau:  {len(beau_freq)} letters")
print(f"Palette in key: {palette_count}/24 ({palette_count/24*100:.1f}%)")
print(f"\nDEFECTOR autokey matches: {match_count}/24 (ene={len(ene_matches)}/13, bcl={len(bcl_matches)}/11)")
print(f"Match positions: {match_positions}")
print(f"Miss positions:  {[p for p, _, _ in deltas]}")
print(f"\nCorrection vector (key deltas at misses):")
print(f"  Positions: {[p for p, _, _ in deltas]}")
print(f"  Values:    {delta_k_vals}")
print(f"  Letters:   {''.join(delta_k_letters)}")
print(f"  Distinct:  {len(set(delta_k_vals))}")

# Bean constraint summary
if inter_27 in beau_keystream and inter_65 in beau_keystream:
    bean_ok = beau_keystream[inter_27] == beau_keystream[inter_65]
    print(f"\nBean EQ (k[{inter_27}]=k[{inter_65}]): {'SATISFIED' if bean_ok else 'VIOLATED'} "
          f"({N2L[beau_keystream[inter_27]]} vs {N2L[beau_keystream[inter_65]]})")
else:
    print(f"\nBean positions not both in crib set")

# Save results
os.makedirs("/home/cpatrick/kryptos/results", exist_ok=True)
results = {
    'experiment': 'E-KEYSTREAM-FORENSICS-V2',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    'bug_fix': 'Corrected crib position mapping: cribs at intermediate positions ENE_S=13..25, BCL_S=47..57',
    'mask': MASK,
    'ct73': CT73_STR,
    'intermediate': INTER_STR,
    'crib_positions': {
        'ene_start': ENE_S,
        'ene_end': ENE_S + 12,
        'bcl_start': BCL_S,
        'bcl_end': BCL_S + 10,
    },
    'beaufort_keystream': {str(p): {'value': beau_keystream[p], 'letter': N2L[beau_keystream[p]]}
                           for p in sorted_positions},
    'beaufort_keystream_letters': beau_letters_str,
    'vigenere_keystream': {str(p): {'value': vig_keystream[p], 'letter': N2L[vig_keystream[p]]}
                           for p in sorted_positions},
    'vigenere_keystream_letters': vig_letters_str,
    'ic_beaufort': ic,
    'defector_matches': match_count,
    'defector_match_positions': match_positions,
    'defector_miss_positions': [p for p, _, _ in deltas],
    'correction_vector_key': delta_k_vals,
    'correction_vector_letters': ''.join(delta_k_letters),
    'bean_positions': {'inter_27': inter_27, 'inter_65': inter_65},
    'bean_satisfied': beau_keystream.get(inter_27) == beau_keystream.get(inter_65) if (inter_27 in beau_keystream and inter_65 in beau_keystream) else None,
}

outpath = "/home/cpatrick/kryptos/results/e_keystream_forensics_v2.json"
with open(outpath, "w") as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nArtifact: {outpath}")
print(f"Repro: PYTHONPATH=src python3 -u scripts/analysis/e_keystream_forensics_v2.py")
