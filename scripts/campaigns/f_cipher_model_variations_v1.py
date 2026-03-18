#!/usr/bin/env python3
"""Systematic test of ALL plausible cipher model variations to break 15/24 ceiling.

Tests 8 categories of variations on the DEFECTOR:AZ_beau+col7+null-mask model:
1. Different autokey feedback offsets (1-26)
2. CT-feedback autokey instead of PT-feedback
3. Quagmire II tableau instead of straight Beaufort
4. Small post-operations (Caesar, reverse, rail fence, atbash)
5. Different transpositions (keyword-ordered col7, col5, double trans)
6. Different primers (not DEFECTOR)
7. Variant Beaufort instead of Beaufort
8. Mixed-alphabet autokey (KA primer, AZ feedback or vice versa)

Known baseline: DEFECTOR:AZ_beau+col7 = 15/24 (ene=7/13, bcl=8/11)
"""

import sys, time, json
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT

CT97 = CT
N = 97; N_PT = 73; N_NULLS = 24
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63

# Known 15/24 mask (MASKS_24[0])
MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])

KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[chr(i+65)] for i in range(26)]
KA_TO_AZ = [ord(KA_STR[i])-65 for i in range(26)]

DEFECTOR_AZ = [ord(c)-65 for c in "DEFECTOR"]
ENE_NUMS = [ord(c)-65 for c in ENE_WORD]
BCL_NUMS = [ord(c)-65 for c in BCL_WORD]

# Crib shifted positions for this mask (n1=8 nulls before 21, n2=16 before 63)
n1 = sum(1 for p in MASK if p < ENE_START)  # 8
n2 = sum(1 for p in MASK if p < BCL_START)  # 16
ENE_S = ENE_START - n1  # 13
BCL_S = BCL_START - n2  # 47

# Columnar permutation utilities
def columnar_perm(n, width):
    grid = []
    for row in range((n + width - 1) // width):
        start = row * width
        grid.append(list(range(start, min(start+width, n))))
    perm = []
    for col in range(width):
        for row in range(len(grid)):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0]*len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

# Pre-compute permutations
PERM_COL7 = reverse_perm(columnar_perm(N_PT, 7))
PERM_COL5 = reverse_perm(columnar_perm(N_PT, 5))
PERM_COL8 = reverse_perm(columnar_perm(N_PT, 8))
PERM_IDENTITY = list(range(N_PT))

# Keyword-ordered col7: KRYPTOS letters sorted -> K(10)<O(14)<P(15)<R(17)<S(18)<T(19)<Y(24)
# positions 0-6 in grid: K=col0, R=col1, Y=col2, P=col3, T=col4, O=col5, S=col6
# Sorted by letter value: K(0),O(5),P(3),R(1),S(6),T(4),Y(2) -> column read order [0,5,3,1,6,4,2]
def keyword_columnar_perm(n, width, col_order):
    """col_order[i] = which column to read i-th."""
    grid = []
    for row in range((n + width - 1) // width):
        start = row * width
        grid.append(list(range(start, min(start+width, n))))
    perm = []
    for col in col_order:
        for row in range(len(grid)):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

# KRYPTOS-ordered col7: sort by letter -> K(10)<O(14)<P(15)<R(17)<S(18)<T(19)<Y(24)
# Original positions: K=0, R=1, Y=2, P=3, T=4, O=5, S=6
# Sorted: K(0), O(5), P(3), R(1), S(6), T(4), Y(2)
KRYPTOS_COL_ORDER = [0, 5, 3, 1, 6, 4, 2]
PERM_COL7_KRYPTOS = reverse_perm(keyword_columnar_perm(N_PT, 7, KRYPTOS_COL_ORDER))

# SEVEN-ordered col7 (5 letters, but we need 7 columns)
# For col5 with SEVEN: S(18)<E(4)<V(21)<E(4)<N(13) -> sort indices: E(1),E(3),N(4),S(0),V(2)
SEVEN_COL5_ORDER = [1, 3, 4, 0, 2]
PERM_COL5_SEVEN = reverse_perm(keyword_columnar_perm(N_PT, 5, SEVEN_COL5_ORDER))

# Double transpositions
def compose_perm(perm_a, perm_b, n):
    """Apply perm_a then perm_b: result[i] = perm_a[perm_b[i]]"""
    return [perm_a[perm_b[i]] for i in range(n)]

PERM_COL7_THEN_COL5 = compose_perm(PERM_COL7, PERM_COL5, N_PT)
PERM_COL5_THEN_COL7 = compose_perm(PERM_COL5, PERM_COL7, N_PT)

# Extract 73 chars from CT97 using mask
CT73_RAW = [ord(CT97[i])-65 for i in range(97) if i not in MASK]
assert len(CT73_RAW) == 73

def score_pt(pt_nums, ene_s=ENE_S, bcl_s=BCL_S):
    """Score plaintext against cribs. Returns (total, ene, bcl)."""
    e = sum(1 for j in range(13) if ene_s+j < len(pt_nums) and pt_nums[ene_s+j] == ENE_NUMS[j])
    b = sum(1 for j in range(11) if bcl_s+j < len(pt_nums) and pt_nums[bcl_s+j] == BCL_NUMS[j])
    return e+b, e, b

def nums_to_str(nums):
    return ''.join(chr(n+65) for n in nums)

# =====================================================================
# CORE DECRYPT FUNCTIONS
# =====================================================================

def autokey_pt_feedback(ct_nums, primer_nums, offset, beau=True):
    """Autokey decrypt with PT feedback at specified offset.
    Standard: offset = len(primer), key[i] = PT[i-offset] for i >= len(primer)
    Here: primer used for first len(primer) positions, then PT[i-offset] used.
    """
    n = len(ct_nums)
    L = len(primer_nums)
    pt = [0] * n
    for i in range(n):
        if i < L:
            k = primer_nums[i]
        else:
            fb_idx = i - offset
            if fb_idx < 0:
                k = primer_nums[i % L]  # wrap primer if offset > L
            else:
                k = pt[fb_idx]
        if beau:
            pt[i] = (k - ct_nums[i]) % 26
        else:  # vigenere
            pt[i] = (ct_nums[i] - k) % 26

    return pt

def autokey_ct_feedback(ct_nums, primer_nums, offset, beau=True):
    """Autokey decrypt with CT feedback at specified offset."""
    n = len(ct_nums)
    L = len(primer_nums)
    pt = [0] * n
    for i in range(n):
        if i < L:
            k = primer_nums[i]
        else:
            fb_idx = i - offset
            if fb_idx < 0:
                k = primer_nums[i % L]
            else:
                k = ct_nums[fb_idx]
        if beau:
            pt[i] = (k - ct_nums[i]) % 26
        else:  # vigenere
            pt[i] = (ct_nums[i] - k) % 26
    return pt

def var_beaufort_autokey_pt(ct_nums, primer_nums, offset):
    """Variant Beaufort: P = (C + K) mod 26, autokey with PT feedback."""
    n = len(ct_nums)
    L = len(primer_nums)
    pt = [0] * n
    for i in range(n):
        if i < L:
            k = primer_nums[i]
        else:
            fb_idx = i - offset
            if fb_idx < 0:
                k = primer_nums[i % L]
            else:
                k = pt[fb_idx]
        pt[i] = (ct_nums[i] + k) % 26
    return pt

def q2_decrypt(ct_nums, key_nums):
    """Quagmire II tableau: P = KA[(KA.index(C) - AZ.index(key)) % 26]
    CT letters indexed by KA, key letters indexed by AZ.
    """
    pt = [0] * len(ct_nums)
    for i in range(len(ct_nums)):
        c_ka = AZ_TO_KA[ct_nums[i]]  # CT letter's KA index
        k_az = key_nums[i]            # Key in AZ
        pt_ka_idx = (c_ka - k_az) % 26
        pt[i] = KA_TO_AZ[pt_ka_idx]   # Convert KA index back to AZ
    return pt

def q2_autokey_pt(ct_nums, primer_nums, offset):
    """Q2 autokey with PT feedback. primer in AZ."""
    n = len(ct_nums)
    L = len(primer_nums)
    pt = [0] * n
    for i in range(n):
        if i < L:
            k = primer_nums[i]
        else:
            fb_idx = i - offset
            if fb_idx < 0:
                k = primer_nums[i % L]
            else:
                k = pt[fb_idx]
        c_ka = AZ_TO_KA[ct_nums[i]]
        pt_ka_idx = (c_ka - k) % 26
        pt[i] = KA_TO_AZ[pt_ka_idx]
    return pt

def q2_autokey_ct(ct_nums, primer_nums, offset):
    """Q2 autokey with CT feedback. primer in AZ."""
    n = len(ct_nums)
    L = len(primer_nums)
    pt = [0] * n
    for i in range(n):
        if i < L:
            k = primer_nums[i]
        else:
            fb_idx = i - offset
            if fb_idx < 0:
                k = primer_nums[i % L]
            else:
                k = ct_nums[fb_idx]
        c_ka = AZ_TO_KA[ct_nums[i]]
        pt_ka_idx = (c_ka - k) % 26
        pt[i] = KA_TO_AZ[pt_ka_idx]
    return pt

def apply_perm(ct73_nums, perm):
    """Apply inverse transposition permutation."""
    return [ct73_nums[perm[i]] for i in range(len(ct73_nums))]

# =====================================================================
# COLLECTION OF RESULTS
# =====================================================================
all_results = []
THRESHOLD = 14  # Report everything >= 14

def record(score, ene, bcl, pt_str, desc):
    all_results.append((score, ene, bcl, pt_str[:60], desc))
    if score >= THRESHOLD:
        print(f"  ** {score}/24 (ene={ene}/13, bcl={bcl}/11) {desc}")
        print(f"     PT: {pt_str[:60]}")

t0 = time.time()

# =====================================================================
# VERIFY BASELINE
# =====================================================================
print("="*70)
print("VERIFICATION: DEFECTOR:AZ_beau + col7 + mask0 = 15/24")
print("="*70)

ct73_t = apply_perm(CT73_RAW, PERM_COL7)
pt_base = autokey_pt_feedback(ct73_t, DEFECTOR_AZ, offset=8, beau=True)
sc, e, b = score_pt(pt_base)
print(f"  Baseline: {sc}/24 (ene={e}/13, bcl={b}/11)")
print(f"  PT: {nums_to_str(pt_base)[:60]}")
assert sc == 15, f"Baseline verification failed: {sc}/24"
print("  VERIFIED OK")
print()

# =====================================================================
# TEST 1: DIFFERENT AUTOKEY FEEDBACK OFFSETS (1-26)
# =====================================================================
print("="*70)
print("TEST 1: Different autokey feedback offsets (1-26)")
print("="*70)
print("Standard model: offset=8 (DEFECTOR length). Testing all 1-26.")
print()

for offset in range(1, 27):
    pt = autokey_pt_feedback(ct73_t, DEFECTOR_AZ, offset=offset, beau=True)
    sc, e, b = score_pt(pt)
    tag = " <-- BASELINE" if offset == 8 else ""
    if sc >= THRESHOLD or offset == 8:
        print(f"  offset={offset:2d}: {sc}/24 (ene={e}/13, bcl={b}/11){tag}")
    record(sc, e, b, nums_to_str(pt), f"T1:beau_pt_feedback:offset={offset}")

# Also test Vigenere with different offsets
print()
print("  Vigenere variant:")
for offset in range(1, 27):
    pt = autokey_pt_feedback(ct73_t, DEFECTOR_AZ, offset=offset, beau=False)
    sc, e, b = score_pt(pt)
    if sc >= THRESHOLD:
        print(f"  offset={offset:2d}: {sc}/24 (ene={e}/13, bcl={b}/11) VIG")
    record(sc, e, b, nums_to_str(pt), f"T1:vig_pt_feedback:offset={offset}")

print()

# =====================================================================
# TEST 2: CT-FEEDBACK AUTOKEY
# =====================================================================
print("="*70)
print("TEST 2: CT-feedback autokey (DEFECTOR primer, AZ)")
print("="*70)

for offset in range(1, 14):
    # Beaufort CT-feedback
    pt = autokey_ct_feedback(ct73_t, DEFECTOR_AZ, offset=offset, beau=True)
    sc, e, b = score_pt(pt)
    if sc >= THRESHOLD or offset == 8:
        print(f"  beau ct-fb offset={offset:2d}: {sc}/24 (ene={e}/13, bcl={b}/11)")
    record(sc, e, b, nums_to_str(pt), f"T2:beau_ct_feedback:offset={offset}")

    # Vigenere CT-feedback
    pt = autokey_ct_feedback(ct73_t, DEFECTOR_AZ, offset=offset, beau=False)
    sc, e, b = score_pt(pt)
    if sc >= THRESHOLD or offset == 8:
        print(f"  vig  ct-fb offset={offset:2d}: {sc}/24 (ene={e}/13, bcl={b}/11)")
    record(sc, e, b, nums_to_str(pt), f"T2:vig_ct_feedback:offset={offset}")

# Also KA alphabet
for offset in range(1, 14):
    # Beaufort CT-feedback on KA
    ct73_ka = [AZ_TO_KA[c] for c in ct73_t]
    primer_ka = [KA_IDX[c] for c in "DEFECTOR"]
    n = 73; L = 8
    pt_ka = [0]*n
    for i in range(n):
        if i < L:
            k = primer_ka[i]
        else:
            fb_idx = i - offset
            if fb_idx < 0: k = primer_ka[i % L]
            else: k = ct73_ka[fb_idx]
        pt_ka[i] = (k - ct73_ka[i]) % 26
    pt_az = [KA_TO_AZ[p] for p in pt_ka]
    sc, e, b = score_pt(pt_az)
    if sc >= THRESHOLD:
        print(f"  KA beau ct-fb offset={offset:2d}: {sc}/24 (ene={e}/13, bcl={b}/11)")
    record(sc, e, b, nums_to_str(pt_az), f"T2:KA_beau_ct_feedback:offset={offset}")

print()

# =====================================================================
# TEST 3: QUAGMIRE II AUTOKEY
# =====================================================================
print("="*70)
print("TEST 3: Quagmire II (KA body, AZ key column) autokey")
print("="*70)

# Q2 PT-feedback with DEFECTOR primer, various offsets
for offset in [5, 7, 8, 13]:
    pt = q2_autokey_pt(ct73_t, DEFECTOR_AZ, offset=offset)
    sc, e, b = score_pt(pt)
    print(f"  Q2 pt-fb DEFECTOR offset={offset}: {sc}/24 (ene={e}/13, bcl={b}/11)")
    record(sc, e, b, nums_to_str(pt), f"T3:Q2_pt_feedback:DEFECTOR:offset={offset}")

# Q2 CT-feedback
for offset in [5, 7, 8, 13]:
    pt = q2_autokey_ct(ct73_t, DEFECTOR_AZ, offset=offset)
    sc, e, b = score_pt(pt)
    print(f"  Q2 ct-fb DEFECTOR offset={offset}: {sc}/24 (ene={e}/13, bcl={b}/11)")
    record(sc, e, b, nums_to_str(pt), f"T3:Q2_ct_feedback:DEFECTOR:offset={offset}")

# Q2 with various indicator letters (single-letter primer)
for indicator in "KADEFBCSZ":
    ind_num = [ord(indicator)-65]
    for offset in [1, 5, 7, 8]:
        pt = q2_autokey_pt(ct73_t, ind_num, offset=offset)
        sc, e, b = score_pt(pt)
        if sc >= THRESHOLD:
            print(f"  Q2 pt-fb ind={indicator} offset={offset}: {sc}/24")
        record(sc, e, b, nums_to_str(pt), f"T3:Q2_pt:ind={indicator}:offset={offset}")

# Q2 with KRYPTOS as primer
kryptos_az = [ord(c)-65 for c in "KRYPTOS"]
for offset in [5, 7, 8, 13]:
    pt = q2_autokey_pt(ct73_t, kryptos_az, offset=offset)
    sc, e, b = score_pt(pt)
    if sc >= THRESHOLD or offset == 7:
        print(f"  Q2 pt-fb KRYPTOS offset={offset}: {sc}/24 (ene={e}/13, bcl={b}/11)")
    record(sc, e, b, nums_to_str(pt), f"T3:Q2_pt_feedback:KRYPTOS:offset={offset}")

# Q2 with SEVEN as primer
seven_az = [ord(c)-65 for c in "SEVEN"]
for offset in [5, 7, 8, 13]:
    pt = q2_autokey_pt(ct73_t, seven_az, offset=offset)
    sc, e, b = score_pt(pt)
    if sc >= THRESHOLD:
        print(f"  Q2 pt-fb SEVEN offset={offset}: {sc}/24")
    record(sc, e, b, nums_to_str(pt), f"T3:Q2_pt_feedback:SEVEN:offset={offset}")

print()

# =====================================================================
# TEST 4: POST-OPERATIONS AFTER BEAUFORT AUTOKEY
# =====================================================================
print("="*70)
print("TEST 4: Small post-operations after Beaufort autokey decrypt")
print("="*70)

# Start with the baseline 15/24 plaintext
pt_base_nums = autokey_pt_feedback(ct73_t, DEFECTOR_AZ, offset=8, beau=True)

# 4a: Caesar shift 1-25
print("  4a: Caesar shifts 1-25")
for shift in range(1, 26):
    pt_shifted = [(p + shift) % 26 for p in pt_base_nums]
    sc, e, b = score_pt(pt_shifted)
    if sc >= THRESHOLD:
        print(f"    Caesar +{shift}: {sc}/24 (ene={e}/13, bcl={b}/11)")
    record(sc, e, b, nums_to_str(pt_shifted), f"T4:caesar_shift={shift}")

# 4b: Reverse the PT
print("  4b: Reverse")
pt_rev = list(reversed(pt_base_nums))
# For reversed PT, crib positions change: ene_s -> 73-1-ene_s-12, bcl_s -> 73-1-bcl_s-10
rev_ene_s = 73 - ENE_S - 13
rev_bcl_s = 73 - BCL_S - 11
sc, e, b = score_pt(pt_rev, ene_s=rev_ene_s, bcl_s=rev_bcl_s)
print(f"    Reverse: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_rev), f"T4:reverse")
# Also check reversed with standard positions (in case something weird)
sc2, e2, b2 = score_pt(pt_rev)
if sc2 >= THRESHOLD:
    print(f"    Reverse (std pos): {sc2}/24")
record(sc2, e2, b2, nums_to_str(pt_rev), f"T4:reverse_stdpos")

# 4c: Rail fence depth 2-5
print("  4c: Rail fence (undo)")
for depth in range(2, 6):
    # Undo rail fence: figure out the reading order
    indices = [[] for _ in range(depth)]
    rail = 0; dr = 1
    for i in range(73):
        indices[rail].append(i)
        rail += dr
        if rail == depth-1: dr = -1
        elif rail == 0: dr = 1
    read_order = []
    for r in range(depth):
        read_order.extend(indices[r])
    # Build inverse: inv_order[read_order[i]] = i
    inv_order = [0]*73
    for i, ro in enumerate(read_order):
        inv_order[ro] = i
    # Apply inverse rail fence to PT
    pt_rf = [pt_base_nums[inv_order[i]] for i in range(73)]
    sc, e, b = score_pt(pt_rf)
    if sc >= THRESHOLD:
        print(f"    Rail fence d={depth} (undo): {sc}/24")
    record(sc, e, b, nums_to_str(pt_rf), f"T4:rail_fence_undo_d={depth}")
    # Also apply rail fence forward
    pt_rf2 = [pt_base_nums[read_order[i]] for i in range(73)]
    sc, e, b = score_pt(pt_rf2)
    if sc >= THRESHOLD:
        print(f"    Rail fence d={depth} (apply): {sc}/24")
    record(sc, e, b, nums_to_str(pt_rf2), f"T4:rail_fence_apply_d={depth}")

# 4d: Atbash (A<->Z, B<->Y, etc.)
print("  4d: Atbash")
pt_atbash = [(25 - p) % 26 for p in pt_base_nums]
sc, e, b = score_pt(pt_atbash)
print(f"    Atbash: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_atbash), f"T4:atbash")

# 4e: ROT13
print("  4e: ROT13")
pt_rot13 = [(p + 13) % 26 for p in pt_base_nums]
sc, e, b = score_pt(pt_rot13)
print(f"    ROT13: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_rot13), f"T4:rot13")

# 4f: KA permutation of PT (apply AZ->KA mapping to each PT letter)
print("  4f: AZ->KA permutation of PT")
pt_ka = [AZ_TO_KA[p] for p in pt_base_nums]
sc, e, b = score_pt(pt_ka)
print(f"    AZ->KA: {sc}/24")
record(sc, e, b, nums_to_str(pt_ka), f"T4:az_to_ka")
pt_ka2 = [KA_TO_AZ[p] for p in pt_base_nums]
sc, e, b = score_pt(pt_ka2)
print(f"    KA->AZ: {sc}/24")
record(sc, e, b, nums_to_str(pt_ka2), f"T4:ka_to_az")

print()

# =====================================================================
# TEST 5: DIFFERENT TRANSPOSITIONS
# =====================================================================
print("="*70)
print("TEST 5: Different transpositions before Beaufort autokey")
print("="*70)

trans_options = [
    ("col7_kryptos_ordered", PERM_COL7_KRYPTOS),
    ("col5_standard", PERM_COL5),
    ("col5_seven_ordered", PERM_COL5_SEVEN),
    ("col8_standard", reverse_perm(columnar_perm(N_PT, 8))),
    ("col7_then_col5", PERM_COL7_THEN_COL5),
    ("col5_then_col7", PERM_COL5_THEN_COL7),
    ("identity", PERM_IDENTITY),
]

for trans_name, perm in trans_options:
    ct73_t2 = apply_perm(CT73_RAW, perm)
    pt = autokey_pt_feedback(ct73_t2, DEFECTOR_AZ, offset=8, beau=True)
    sc, e, b = score_pt(pt)
    tag = ""
    if sc >= THRESHOLD:
        tag = " ***"
    print(f"  {trans_name:25s}: {sc}/24 (ene={e}/13, bcl={b}/11){tag}")
    record(sc, e, b, nums_to_str(pt), f"T5:trans={trans_name}:beau:DEFECTOR")

# Also test with KRYPTOS keyword
print()
print("  With KRYPTOS primer:")
for trans_name, perm in trans_options:
    ct73_t2 = apply_perm(CT73_RAW, perm)
    pt = autokey_pt_feedback(ct73_t2, kryptos_az, offset=7, beau=True)
    sc, e, b = score_pt(pt)
    if sc >= THRESHOLD:
        print(f"  KRYPTOS:beau {trans_name}: {sc}/24 ***")
    record(sc, e, b, nums_to_str(pt), f"T5:trans={trans_name}:beau:KRYPTOS")

# Test reverse column order for col7 (read columns bottom-to-top)
print()
print("  Reversed col7 (bottom-to-top):")
fwd_perm = columnar_perm(N_PT, 7)
# Reverse within each column
n_rows = (N_PT + 6) // 7  # 11
rev_perm = []
for col in range(7):
    col_positions = [fwd_perm[i] for i in range(len(fwd_perm)) if i // n_rows == col or True]
# Actually, let's do this properly
col_indices = [[] for _ in range(7)]
for row in range((N_PT + 6) // 7):
    for col in range(7):
        pos = row * 7 + col
        if pos < N_PT:
            col_indices[col].append(pos)
# Reverse each column's positions
rev_col_perm = []
for col in range(7):
    rev_col_perm.extend(reversed(col_indices[col]))
PERM_COL7_REV = reverse_perm(rev_col_perm)
ct73_t2 = apply_perm(CT73_RAW, PERM_COL7_REV)
pt = autokey_pt_feedback(ct73_t2, DEFECTOR_AZ, offset=8, beau=True)
sc, e, b = score_pt(pt)
print(f"  col7_reversed_cols: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt), f"T5:trans=col7_reversed_cols:beau:DEFECTOR")

print()

# =====================================================================
# TEST 6: DIFFERENT PRIMERS
# =====================================================================
print("="*70)
print("TEST 6: Different primers (with AZ Beaufort + col7)")
print("="*70)

# 6a: Single-letter primers (all 26)
print("  6a: Single-letter primers (key[0]=X, then PT feedback from pos 1)")
best_1letter = (0, '', '')
for k in range(26):
    pt = autokey_pt_feedback(ct73_t, [k], offset=1, beau=True)
    sc, e, b = score_pt(pt)
    if sc >= THRESHOLD:
        print(f"    primer={chr(k+65)}: {sc}/24 (ene={e}/13, bcl={b}/11)")
    record(sc, e, b, nums_to_str(pt), f"T6:primer={chr(k+65)}:beau:offset=1")
    if sc > best_1letter[0]:
        best_1letter = (sc, chr(k+65), nums_to_str(pt))
print(f"  Best 1-letter: {best_1letter[0]}/24 (primer={best_1letter[1]})")

# 6b: Two-letter primers (all 676)
print("  6b: Two-letter primers (676 combos)")
best_2letter = (0, '', '')
count_14plus = 0
for k1 in range(26):
    for k2 in range(26):
        pt = autokey_pt_feedback(ct73_t, [k1, k2], offset=2, beau=True)
        sc, e, b = score_pt(pt)
        if sc >= THRESHOLD:
            count_14plus += 1
            pstr = chr(k1+65) + chr(k2+65)
            if sc > best_2letter[0]:
                best_2letter = (sc, pstr, nums_to_str(pt))
                print(f"    primer={pstr}: {sc}/24 (ene={e}/13, bcl={b}/11)")
        record(sc, e, b, nums_to_str(pt), f"T6:primer={chr(k1+65)}{chr(k2+65)}:beau:offset=2")
print(f"  Best 2-letter: {best_2letter[0]}/24 (primer={best_2letter[1]}), {count_14plus} configs >= 14")

# 6c: Named primers
print("  6c: Named primers")
named_primers = [
    ("KRYPTOSA", [ord(c)-65 for c in "KRYPTOSA"]),
    ("SEVENKRY", [ord(c)-65 for c in "SEVENKRY"]),
    ("SEVEN", [ord(c)-65 for c in "SEVEN"]),
    ("KRYPTOS", kryptos_az),
    ("BERLINCL", [ord(c)-65 for c in "BERLINCL"]),
    ("EASTNORT", [ord(c)-65 for c in "EASTNORT"]),
    ("PALIMPSE", [ord(c)-65 for c in "PALIMPSE"]),
    ("ABSCISSA", [ord(c)-65 for c in "ABSCISSA"]),
    ("COLOPHON", [ord(c)-65 for c in "COLOPHON"]),
]

# Also derive primer from crib positions
# At ENE crib: key = (CT + PT) mod 26 for Beaufort
ene_keys = [(ct73_t[ENE_S+j] + ENE_NUMS[j]) % 26 for j in range(8) if ENE_S+j < 73]
named_primers.append(("ENE_KEYS_8", ene_keys[:8]))

# First 8 of extracted CT
named_primers.append(("CT73_FIRST8", list(ct73_t[:8])))

# DEFECTOR encrypted by KRYPTOS (Beaufort)
def_enc = [(kryptos_az[i%7] - DEFECTOR_AZ[i]) % 26 for i in range(8)]
named_primers.append(("DEF_ENC_KRYPTOS", def_enc))

for name, primer in named_primers:
    L = len(primer)
    pt = autokey_pt_feedback(ct73_t, primer, offset=L, beau=True)
    sc, e, b = score_pt(pt)
    tag = " ***" if sc >= THRESHOLD else ""
    print(f"    {name:20s} (L={L}): {sc}/24 (ene={e}/13, bcl={b}/11){tag}")
    record(sc, e, b, nums_to_str(pt), f"T6:primer={name}:beau:offset={L}")
    # Also with offset=8 (DEFECTOR length)
    if L != 8:
        pt2 = autokey_pt_feedback(ct73_t, primer, offset=8, beau=True)
        sc2, e2, b2 = score_pt(pt2)
        if sc2 >= THRESHOLD:
            print(f"    {name:20s} (L={L},off=8): {sc2}/24 ***")
        record(sc2, e2, b2, nums_to_str(pt2), f"T6:primer={name}:beau:offset=8")

print()

# =====================================================================
# TEST 7: VARIANT BEAUFORT AUTOKEY
# =====================================================================
print("="*70)
print("TEST 7: Variant Beaufort autokey (P = C + K mod 26)")
print("="*70)

for offset in [1, 5, 7, 8, 13]:
    pt = var_beaufort_autokey_pt(ct73_t, DEFECTOR_AZ, offset=offset)
    sc, e, b = score_pt(pt)
    tag = " ***" if sc >= THRESHOLD else ""
    print(f"  VarBeau pt-fb DEFECTOR offset={offset}: {sc}/24 (ene={e}/13, bcl={b}/11){tag}")
    record(sc, e, b, nums_to_str(pt), f"T7:varbeau_pt:DEFECTOR:offset={offset}")

# With Vigenere: P = (C - K) mod 26 (standard)
print("  Standard Vigenere autokey for comparison:")
for offset in [1, 5, 7, 8, 13]:
    pt = autokey_pt_feedback(ct73_t, DEFECTOR_AZ, offset=offset, beau=False)
    sc, e, b = score_pt(pt)
    if sc >= THRESHOLD or offset == 8:
        print(f"  Vig pt-fb DEFECTOR offset={offset}: {sc}/24 (ene={e}/13, bcl={b}/11)")
    record(sc, e, b, nums_to_str(pt), f"T7:vig_pt:DEFECTOR:offset={offset}")

print()

# =====================================================================
# TEST 8: MIXED ALPHABET AUTOKEY
# =====================================================================
print("="*70)
print("TEST 8: Mixed-alphabet autokey")
print("="*70)

# 8a: KA for primer portion, AZ for autokey feedback
print("  8a: KA-indexed primer (first 8), AZ PT-feedback (pos 9+)")
primer_ka_nums = [KA_IDX[c] for c in "DEFECTOR"]  # DEFECTOR in KA indexing
pt_mixed = [0]*73
for i in range(73):
    if i < 8:
        k = primer_ka_nums[i]  # KA-indexed
    else:
        k = pt_mixed[i-8]  # AZ-indexed PT feedback
    pt_mixed[i] = (k - ct73_t[i]) % 26  # Beaufort
sc, e, b = score_pt(pt_mixed)
print(f"    KA-primer + AZ-feedback: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_mixed), "T8:KA_primer_AZ_feedback")

# 8b: AZ for primer, KA for feedback
print("  8b: AZ-indexed primer (first 8), KA PT-feedback (pos 9+)")
pt_mixed2 = [0]*73
for i in range(73):
    if i < 8:
        k = DEFECTOR_AZ[i]  # AZ-indexed
    else:
        k = AZ_TO_KA[pt_mixed2[i-8]]  # Convert PT to KA index for feedback
    pt_mixed2[i] = (k - ct73_t[i]) % 26  # Beaufort
sc, e, b = score_pt(pt_mixed2)
print(f"    AZ-primer + KA-feedback: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_mixed2), "T8:AZ_primer_KA_feedback")

# 8c: Full KA Beaufort autokey
print("  8c: Full KA Beaufort autokey (both primer and feedback in KA)")
ct73_ka = [AZ_TO_KA[c] for c in ct73_t]
defector_ka = [KA_IDX[c] for c in "DEFECTOR"]
pt_fullka = [0]*73
for i in range(73):
    if i < 8:
        k = defector_ka[i]
    else:
        k = pt_fullka[i-8]
    pt_fullka[i] = (k - ct73_ka[i]) % 26
# Convert back to AZ for scoring
pt_fullka_az = [KA_TO_AZ[p] for p in pt_fullka]
sc, e, b = score_pt(pt_fullka_az)
print(f"    Full KA Beaufort: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_fullka_az), "T8:full_KA_beaufort")

# 8d: CT indexed in KA, key in AZ
print("  8d: CT in KA, key in AZ (Q2-like but Beaufort)")
pt_q2beau = [0]*73
for i in range(73):
    c_ka = AZ_TO_KA[ct73_t[i]]  # CT -> KA index
    if i < 8:
        k_az = DEFECTOR_AZ[i]
    else:
        k_az = pt_q2beau[i-8]  # PT feedback in AZ
    pt_q2beau[i] = (k_az - c_ka) % 26  # Beaufort
sc, e, b = score_pt(pt_q2beau)
print(f"    CT_KA - key_AZ Beaufort: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_q2beau), "T8:CT_KA_key_AZ_beaufort")

# 8e: The real Kryptos Q2 tableau autokey
print("  8e: True Q2 tableau autokey (DEFECTOR, offsets 5,7,8,13)")
for offset in [5, 7, 8, 13]:
    pt = q2_autokey_pt(ct73_t, DEFECTOR_AZ, offset=offset)
    sc, e, b = score_pt(pt)
    tag = " ***" if sc >= THRESHOLD else ""
    print(f"    Q2 autokey DEFECTOR offset={offset}: {sc}/24{tag}")
    record(sc, e, b, nums_to_str(pt), f"T8:Q2_autokey:DEFECTOR:offset={offset}")

print()

# =====================================================================
# BONUS TEST 9: COMBINATORIAL SEARCH
# =====================================================================
print("="*70)
print("TEST 9: Combinatorial - multiple small variations at once")
print("="*70)

# 9a: Pre-operation on CT before Beaufort: Caesar shift the extracted CT
print("  9a: Caesar shift on extracted CT BEFORE Beaufort decrypt")
for shift in range(1, 26):
    ct73_shifted = [(c + shift) % 26 for c in ct73_t]
    pt = autokey_pt_feedback(ct73_shifted, DEFECTOR_AZ, offset=8, beau=True)
    sc, e, b = score_pt(pt)
    if sc >= THRESHOLD:
        print(f"    CT+{shift} then beau: {sc}/24 (ene={e}/13, bcl={b}/11) ***")
    record(sc, e, b, nums_to_str(pt), f"T9:ct_caesar={shift}:beau:DEFECTOR")

# 9b: Different mask + col7 + beau variations (test the other 5 known masks)
print("  9b: Other known 15/24 masks (should all verify)")
OTHER_MASKS = [
    frozenset([0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95]),
    frozenset([0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95]),
    frozenset([0,1,2,5,8,12,14,20,36,39,41,42,52,55,58,59,74,75,78,84,85,88,93,95]),
    frozenset([0,1,2,5,8,12,14,20,36,38,39,45,52,56,58,59,74,75,78,84,85,87,93,95]),
    frozenset([0,1,2,5,8,12,14,20,36,41,42,44,52,55,58,59,74,75,78,84,85,88,93,96]),
]

for idx, mask in enumerate(OTHER_MASKS):
    ct73_v = [ord(CT97[i])-65 for i in range(97) if i not in mask]
    n1v = sum(1 for p in mask if p < ENE_START)
    n2v = sum(1 for p in mask if p < BCL_START)
    es_v = ENE_START - n1v
    bs_v = BCL_START - n2v
    ct73_t_v = apply_perm(ct73_v, PERM_COL7)
    pt = autokey_pt_feedback(ct73_t_v, DEFECTOR_AZ, offset=8, beau=True)
    sc, e, b = score_pt(pt, ene_s=es_v, bcl_s=bs_v)
    print(f"    Mask {idx+1}: {sc}/24 (ene={e}/13, bcl={b}/11)")

# 9c: Beaufort with non-standard feedback: key[i] = PT[i-L] XOR primer[i%L]
print("  9c: Modified feedback: key[i] = (PT[i-8] + DEFECTOR[i%8]) % 26")
pt_modfb = [0]*73
for i in range(73):
    if i < 8:
        k = DEFECTOR_AZ[i]
    else:
        k = (pt_modfb[i-8] + DEFECTOR_AZ[i%8]) % 26
    pt_modfb[i] = (k - ct73_t[i]) % 26
sc, e, b = score_pt(pt_modfb)
print(f"    PT[i-8]+DEFECTOR[i%8] feedback: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_modfb), "T9:modified_feedback_add")

# 9d: key[i] = (PT[i-8] - DEFECTOR[i%8]) % 26
pt_modfb2 = [0]*73
for i in range(73):
    if i < 8:
        k = DEFECTOR_AZ[i]
    else:
        k = (pt_modfb2[i-8] - DEFECTOR_AZ[i%8]) % 26
    pt_modfb2[i] = (k - ct73_t[i]) % 26
sc, e, b = score_pt(pt_modfb2)
print(f"    PT[i-8]-DEFECTOR[i%8] feedback: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_modfb2), "T9:modified_feedback_sub")

# 9e: Running key mode: key[i] = DEFECTOR repeated (periodic, not autokey)
print("  9e: Periodic DEFECTOR (not autokey) for comparison")
pt_periodic = [0]*73
for i in range(73):
    k = DEFECTOR_AZ[i % 8]
    pt_periodic[i] = (k - ct73_t[i]) % 26
sc, e, b = score_pt(pt_periodic)
print(f"    Periodic DEFECTOR: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_periodic), "T9:periodic_defector")

# 9f: Autokey with BOTH PT and CT combined feedback
print("  9f: Combined PT+CT feedback: key[i] = (PT[i-8] + CT[i-8]) % 26")
pt_combined = [0]*73
for i in range(73):
    if i < 8:
        k = DEFECTOR_AZ[i]
    else:
        k = (pt_combined[i-8] + ct73_t[i-8]) % 26
    pt_combined[i] = (k - ct73_t[i]) % 26
sc, e, b = score_pt(pt_combined)
print(f"    Combined PT+CT feedback: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_combined), "T9:combined_ptct_feedback")

# 9g: Transposition AFTER Beaufort (reverse the pipeline order)
print("  9g: Beaufort first (no trans), then col7 transposition on PT")
pt_notrans = autokey_pt_feedback(CT73_RAW, DEFECTOR_AZ, offset=8, beau=True)
pt_then_trans = apply_perm(pt_notrans, PERM_COL7)
sc, e, b = score_pt(pt_then_trans)
print(f"    Beau first, then col7: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_then_trans), "T9:beau_then_col7")
# Inverse direction
inv_col7 = columnar_perm(N_PT, 7)
pt_then_trans2 = [pt_notrans[inv_col7[i]] for i in range(73)]
sc, e, b = score_pt(pt_then_trans2)
print(f"    Beau first, then col7 inv: {sc}/24 (ene={e}/13, bcl={b}/11)")
record(sc, e, b, nums_to_str(pt_then_trans2), "T9:beau_then_col7_inv")

print()

# =====================================================================
# TEST 10: STRIDE AND ROUTE TRANSPOSITIONS
# =====================================================================
print("="*70)
print("TEST 10: Stride and route cipher transpositions")
print("="*70)

# Stride transpositions
for stride in [3, 5, 7, 9, 11, 13]:
    perm_stride = [(i * stride) % 73 for i in range(73)]
    if len(set(perm_stride)) != 73:
        continue  # skip non-bijective strides
    ct73_s = apply_perm(CT73_RAW, perm_stride)
    pt = autokey_pt_feedback(ct73_s, DEFECTOR_AZ, offset=8, beau=True)
    sc, e, b = score_pt(pt)
    if sc >= THRESHOLD:
        print(f"  stride={stride}: {sc}/24 (ene={e}/13, bcl={b}/11) ***")
    record(sc, e, b, nums_to_str(pt), f"T10:stride={stride}:beau:DEFECTOR")

# Spiral reading of 11x7 grid (73 = 11*7 - 4)
# Standard spiral (clockwise from top-left)
print("  Spiral readings of col7 grid:")
n_rows_7 = (73 + 6) // 7  # 11 rows
grid_7 = [[None]*7 for _ in range(n_rows_7)]
idx = 0
for r in range(n_rows_7):
    for c in range(7):
        if idx < 73:
            grid_7[r][c] = idx
            idx += 1

# Clockwise spiral
def spiral_read(grid, nrows, ncols):
    result = []
    top, bottom, left, right = 0, nrows-1, 0, ncols-1
    while top <= bottom and left <= right:
        for c in range(left, right+1):
            if grid[top][c] is not None:
                result.append(grid[top][c])
        top += 1
        for r in range(top, bottom+1):
            if right < ncols and grid[r][right] is not None:
                result.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left-1, -1):
                if grid[bottom][c] is not None:
                    result.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top-1, -1):
                if grid[r][left] is not None:
                    result.append(grid[r][left])
            left += 1
    return [x for x in result if x is not None]

spiral_order = spiral_read(grid_7, n_rows_7, 7)
if len(set(spiral_order)) == 73:
    spiral_inv = [0]*73
    for i, s in enumerate(spiral_order):
        spiral_inv[s] = i
    ct73_sp = [CT73_RAW[spiral_inv[i]] for i in range(73)]
    pt = autokey_pt_feedback(ct73_sp, DEFECTOR_AZ, offset=8, beau=True)
    sc, e, b = score_pt(pt)
    print(f"  spiral_cw_7x11: {sc}/24 (ene={e}/13, bcl={b}/11)")
    record(sc, e, b, nums_to_str(pt), "T10:spiral_cw_7x11:beau:DEFECTOR")

print()

# =====================================================================
# SUMMARY
# =====================================================================
elapsed = time.time() - t0
print("="*70)
print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
print("="*70)

# Count total configs
print(f"Total configurations tested: {len(all_results)}")

# Find all results >= 14
hits_14 = [(s, e, b, pt, d) for s, e, b, pt, d in all_results if s >= 14]
hits_14.sort(key=lambda x: -x[0])

print(f"\nResults >= 14/24: {len(hits_14)}")
print()
for s, e, b, pt, d in hits_14[:30]:
    print(f"  {s}/24 (ene={e}/13, bcl={b}/11) | {d}")
    print(f"    PT: {pt}")

# Find anything above 15
hits_16 = [x for x in hits_14 if x[0] > 15]
if hits_16:
    print("\n" + "!"*70)
    print(f"BREAKTHROUGH: {len(hits_16)} results ABOVE 15/24!")
    print("!"*70)
    for s, e, b, pt, d in hits_16:
        print(f"  {s}/24 (ene={e}/13, bcl={b}/11) | {d}")
        print(f"    PT: {pt}")
else:
    print("\n  No results above 15/24. Ceiling confirmed across all variations.")

# Score distribution
from collections import Counter
dist = Counter(s for s, _, _, _, _ in all_results)
print(f"\nScore distribution:")
for score in sorted(dist.keys(), reverse=True):
    if score >= 10:
        print(f"  {score}/24: {dist[score]} configs")

# Save results
results_file = "/home/cpatrick/kryptos/results/cipher_model_variations_v1.json"
output = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "total_configs": len(all_results),
    "elapsed_seconds": round(elapsed, 1),
    "baseline": "DEFECTOR:AZ_beau+col7+mask0 = 15/24",
    "max_score": max(s for s, _, _, _, _ in all_results),
    "above_15": len(hits_16),
    "hits_14plus": [(s, e, b, pt, d) for s, e, b, pt, d in hits_14],
    "score_distribution": {str(k): v for k, v in sorted(dist.items(), reverse=True)},
    "tests_run": [
        "T1: Feedback offsets 1-26 (Beaufort + Vigenere)",
        "T2: CT-feedback autokey (AZ + KA)",
        "T3: Quagmire II autokey (multiple primers, offsets, indicators)",
        "T4: Post-operations (Caesar, reverse, rail fence, atbash, ROT13, KA perm)",
        "T5: Different transpositions (keyword col7, col5, col8, double, reverse)",
        "T6: Different primers (1-letter x26, 2-letter x676, named x12)",
        "T7: Variant Beaufort autokey",
        "T8: Mixed-alphabet autokey (KA/AZ combinations, Q2 tableau)",
        "T9: Combinatorial (CT shift, modified feedback, periodic, combined, pipeline order)",
        "T10: Stride and spiral transpositions",
    ],
}

with open(results_file, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved to: {results_file}")
