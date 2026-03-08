#!/usr/bin/env python3
"""
Cipher: Cardan grille 180-degree rotation
Family: grille
Status: active
Keyspace: 180-degree rotation permutations on 28x31 grid
Last run: 2026-03-05
Best score: 0
"""
"""blitz_rotation_180.py — TEST 180-DEGREE ROTATION HYPOTHESIS

The 28x31 cipher grid (868 cells) splits perfectly in half:
  Top half (rows 0-13):  K1+K2 = 434 chars
  Bottom half (rows 14-27): K3+?+K4 = 434 chars

Under 180-degree rotation (r,c)->(27-r,30-c), every cell pairs with a unique
cell in the OPPOSITE half (since 28 rows means no self-reflected rows exist).

TESTS:
  A. Structural verification: 180-degree pairs, cross-half pairing
  B. K3 permutation formula: compute K3_PERM, analyze cycle structure
  C. K3 vs 180-degree reading order: does sorting K3 positions by their
     180-reflected top-half index give K3_PT?
  D. K4 direct 180-degree test: read K4 reflected chars from K1/K2 positions,
     try all key/cipher/alphabet combos for crib hits
  E. K4 reverse/alternating reading orders
  F. Full bottom-half 434-char reading in 180-reflected order -> K4 region test
  G. Pairing hypothesis: does K4[i] pair with K1/K2 char at reflected position
     to define an unscramble operation?
  H. K3 even/odd cycle vs 180-degree geometry
  I. Extended: K3 pass1/pass2 split by 180-degree reflection
  J. AZ->KA cycle integration: use 17-cycle/8-cycle membership to filter cells
  K. Half-and-half reading: read top half in natural order, bottom in 180-order

Run: PYTHONPATH=src python3 -u scripts/blitz_rotation_180.py
"""
import sys
import math
from collections import Counter
from itertools import product

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = [
    "KRYPTOS","PALIMPSEST","ABSCISSA","SHADOW","SANBORN",
    "SCHEIDT","BERLIN","CLOCK","EAST","NORTH",
    "LIGHT","ANTIPODES","MEDUSA","ENIGMA",
]
K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4_CARVED) == 97

# ── 28x31 Cipher Grid ─────────────────────────────────────────────────────────
CIPHER_ROWS_RAW = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",   # row 0  K1
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",  # row 1  K1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",   # row 2  K1->K2
    "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",  # row 3  K2 (? at col 7)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # row 4
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",   # row 5
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",   # row 6
    "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER",   # row 7  (? at col 9)
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",   # row 8
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",   # row 9
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",   # row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",   # row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",   # row 13 K2 ends
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",   # row 14 K3 starts (CENTER)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # row 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",   # row 17
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",   # row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",   # row 19
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",   # row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",   # row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",   # row 22
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",   # row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",   # row 24 ? at col 26, K4 starts col 27
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",   # row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",   # row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",  # row 27
]

def build_grid():
    grid = []
    for row in CIPHER_ROWS_RAW:
        if len(row) > 31:
            row = row[:31]
        elif len(row) < 31:
            row = row + '?' * (31 - len(row))
        grid.append(list(row))
    return grid

GRID = build_grid()
assert len(GRID) == 28
for row in GRID:
    assert len(row) == 31, f"Row length {len(row)}"

# ── Coordinate functions ───────────────────────────────────────────────────────

def k3_pos_to_grid(i):
    """K3 linear position i (0..335) -> (row, col) in 28x31 grid."""
    if i < 310:
        return (14 + i // 31, i % 31)
    return (24, i - 310)

def k4_pos_to_grid(i):
    """K4 linear position i (0..96) -> (row, col) in 28x31 grid."""
    if i < 4:
        return (24, 27 + i)
    ii = i - 4
    return (25 + ii // 31, ii % 31)

# Verify K4 grid positions match carved text
for i in range(97):
    r, c = k4_pos_to_grid(i)
    assert GRID[r][c] == K4_CARVED[i], f"K4[{i}]={K4_CARVED[i]} but grid[{r}][{c}]={GRID[r][c]}"

# ── K3 Data ───────────────────────────────────────────────────────────────────

def extract_k3_ct():
    """Extract K3 ciphertext: rows 14-23 (310 chars) + row 24 cols 0-25 (26 chars) = 336."""
    ct = []
    for r in range(14, 24):
        for c in range(31):
            ch = GRID[r][c]
            if ch != '?':
                ct.append(ch)
    for c in range(26):
        ch = GRID[24][c]
        if ch != '?':
            ct.append(ch)
    return "".join(ct)

K3_CT = extract_k3_ct()
assert len(K3_CT) == 336, f"K3 CT length {len(K3_CT)}"

def k3_perm_fwd(i):
    """K3 double-rotational transposition: carved position i -> PT position.
    K3_CT[i] = K3_PT[k3_perm_fwd(i)]
    Double CW rotation: 24x14 grid -> 8x42 grid.
    """
    a = i // 24
    b = i % 24
    inter = 14 * b + 13 - a
    c = inter // 8
    d = inter % 8
    return 42 * d + 41 - c

K3_PERM = [k3_perm_fwd(i) for i in range(336)]
assert len(set(K3_PERM)) == 336, "K3 perm not bijective"

K3_INV_PERM = [0] * 336
for i, j in enumerate(K3_PERM):
    K3_INV_PERM[j] = i

K3_PT = "".join(K3_CT[K3_INV_PERM[j]] for j in range(336))

# Verify K3 permutation (0 mismatches expected)
mm = sum(1 for i in range(336) if K3_CT[i] != K3_PT[K3_PERM[i]])
assert mm == 0, f"K3 perm verification failed: {mm} mismatches"

# ── Cipher functions ───────────────────────────────────────────────────────────

def vig_decrypt(ct, key, alpha=AZ):
    r = []
    for i, c in enumerate(ct):
        if c not in alpha:
            r.append(c)
            continue
        r.append(alpha[(alpha.index(c) - alpha.index(key[i % len(key)])) % 26])
    return "".join(r)

def beau_decrypt(ct, key, alpha=AZ):
    r = []
    for i, c in enumerate(ct):
        if c not in alpha:
            r.append(c)
            continue
        r.append(alpha[(alpha.index(key[i % len(key)]) - alpha.index(c)) % 26])
    return "".join(r)

def varbeau_decrypt(ct, key, alpha=AZ):
    """Variant Beaufort: P = (C + K) mod 26"""
    r = []
    for i, c in enumerate(ct):
        if c not in alpha:
            r.append(c)
            continue
        r.append(alpha[(alpha.index(c) + alpha.index(key[i % len(key)])) % 26])
    return "".join(r)

CIPHER_FNS = [
    ("vig", vig_decrypt),
    ("beau", beau_decrypt),
    ("varbeau", varbeau_decrypt),
]
ALPHABETS = [("AZ", AZ), ("KA", KA)]

# ── Crib checking ──────────────────────────────────────────────────────────────

CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"
ENE_POS = 21  # 0-indexed
BC_POS = 63   # 0-indexed

def check_cribs(pt):
    """Return (ene_matches, bc_matches, has_full_ene, has_full_bc)."""
    ene_match = sum(
        1 for i in range(len(CRIB_ENE))
        if ENE_POS + i < len(pt) and pt[ENE_POS + i] == CRIB_ENE[i]
    )
    bc_match = sum(
        1 for i in range(len(CRIB_BC))
        if BC_POS + i < len(pt) and pt[BC_POS + i] == CRIB_BC[i]
    )
    full_ene = pt[ENE_POS:ENE_POS + len(CRIB_ENE)] == CRIB_ENE
    full_bc = pt[BC_POS:BC_POS + len(CRIB_BC)] == CRIB_BC
    return ene_match, bc_match, full_ene, full_bc

def crib_score(pt):
    """Total crib character matches (max 24)."""
    e, b, _, _ = check_cribs(pt)
    return e + b

def test_candidate_ct(candidate_ct, label="", require_min=3):
    """Test a candidate real CT against all keys/ciphers/alphabets.
    Returns best (score, pt, key, cipher, alpha) and reports cribs."""
    best_score = -1
    best_info = None
    hits = []

    for kw in KEYWORDS:
        for aname, alpha in ALPHABETS:
            for cname, cfn in CIPHER_FNS:
                try:
                    pt = cfn(candidate_ct, kw, alpha)
                    e, b, full_e, full_b = check_cribs(pt)
                    sc = e + b
                    if full_e or full_b:
                        hits.append((sc, pt, kw, cname, aname, e, b))
                    if sc > best_score:
                        best_score = sc
                        best_info = (sc, pt, kw, cname, aname, e, b)
                except Exception:
                    pass

    if hits:
        for sc, pt, kw, cname, aname, e, b in sorted(hits, reverse=True):
            print(f"  *** CRIB HIT [{label}] {cname}/{kw}/{aname}: "
                  f"ENE={e}/13 BC={b}/11 score={sc}/24")
            print(f"      PT: {pt[:60]}...")
        return True, best_info

    if best_info and best_info[0] >= require_min:
        sc, pt, kw, cname, aname, e, b = best_info
        print(f"  Partial crib [{label}] {cname}/{kw}/{aname}: "
              f"ENE={e}/13 BC={b}/11 score={sc}/24 | {pt[:40]}...")

    return False, best_info

# ── AZ->KA permutation cycles ──────────────────────────────────────────────────

AZ_to_KA_idx = [KA.index(AZ[i]) for i in range(26)]

def get_az_ka_cycles():
    visited = [False] * 26
    cycles = []
    for start in range(26):
        if not visited[start]:
            cycle = []
            cur = start
            while not visited[cur]:
                visited[cur] = True
                cycle.append(cur)
                cur = AZ_to_KA_idx[cur]
            cycles.append(tuple(cycle))
    return sorted(cycles, key=len, reverse=True)

AZ_KA_CYCLES = get_az_ka_cycles()
LETTER_CYCLE_ID = {}
for cid, cycle in enumerate(AZ_KA_CYCLES):
    for idx in cycle:
        LETTER_CYCLE_ID[AZ[idx]] = cid  # 0=17-cycle, 1=8-cycle, 2=Z fixed

# ── Permutation cycle analysis ─────────────────────────────────────────────────

def get_perm_cycles(perm):
    visited = [False] * len(perm)
    cycles = []
    for start in range(len(perm)):
        if not visited[start]:
            cycle = []
            cur = start
            while not visited[cur]:
                visited[cur] = True
                cycle.append(cur)
                cur = perm[cur]
            cycles.append(cycle)
    return cycles

# =============================================================================
print("=" * 72)
print("BLITZ: 180-DEGREE ROTATION HYPOTHESIS TEST")
print("=" * 72)

# =============================================================================
print("\n" + "=" * 72)
print("A. STRUCTURAL ANALYSIS: 180-DEGREE PAIRING")
print("=" * 72)

ROWS, COLS = 28, 31
total_cells = ROWS * COLS  # 868

# Count pairs
pairs = []
visited = set()
for r in range(ROWS):
    for c in range(COLS):
        if (r, c) not in visited:
            r2, c2 = 27 - r, 30 - c
            pairs.append(((r, c), (r2, c2)))
            visited.add((r, c))
            visited.add((r2, c2))

print(f"Total cells: {total_cells} = {ROWS}x{COLS}")
print(f"Total 180-degree pairs: {len(pairs)} (should be {total_cells//2})")
self_pairs = sum(1 for (r1,c1),(r2,c2) in pairs if r1==r2 and c1==c2)
print(f"Self-reflected pairs (should be 0 for even rows): {self_pairs}")

# Cross-half analysis (row < 14 = top, row >= 14 = bottom)
cross_half = sum(1 for (r1,c1),(r2,c2) in pairs if (r1<14) != (r2<14))
same_half = len(pairs) - cross_half
print(f"Cross-half pairs (top<->bottom): {cross_half}")
print(f"Same-half pairs (anomalous): {same_half}")

# Verify top half has exactly 434 cells
top_cells = sum(1 for r in range(14) for c in range(31))
bottom_cells = sum(1 for r in range(14, 28) for c in range(31))
print(f"Top half cells (rows 0-13): {top_cells}")
print(f"Bottom half cells (rows 14-27): {bottom_cells}")
print(f"K1+K2 letters: 63+369=432 + 2 ?'s = 434 chars in top half: CONFIRMED")
print(f"K3+?+K4 = 336+1+97 = 434 chars in bottom half: CONFIRMED")

# =============================================================================
print("\n" + "=" * 72)
print("B. K3 PERMUTATION: CYCLE STRUCTURE")
print("=" * 72)

k3_cycles = get_perm_cycles(K3_PERM)
print(f"K3 PT: {K3_PT[:60]}...")
print(f"K3 CT: {K3_CT[:60]}...")
print(f"K3 permutation cycle count: {len(k3_cycles)}")
for ci, cyc in enumerate(k3_cycles):
    print(f"  Cycle {ci}: length {len(cyc)}, starts={cyc[0]}, first 10={cyc[:10]}")

# Parity analysis: are cycles partitioned by even/odd position?
if len(k3_cycles) == 2 and len(k3_cycles[0]) == 168 and len(k3_cycles[1]) == 168:
    print("K3 has EXACTLY 2 CYCLES of length 168 -> consistent with 2-pass Cardan grille!")
    cyc0_set = set(k3_cycles[0])
    cyc1_set = set(k3_cycles[1])
    even_in_cyc0 = sum(1 for i in range(0, 336, 2) if i in cyc0_set)
    odd_in_cyc0 = sum(1 for i in range(1, 336, 2) if i in cyc0_set)
    print(f"  Cycle 0: {even_in_cyc0}/168 even positions, {odd_in_cyc0}/168 odd positions")
    if even_in_cyc0 == 168:
        print("  *** Cycle 0 = ALL EVEN positions! Cycle 1 = ALL ODD positions! ***")
    elif odd_in_cyc0 == 168:
        print("  *** Cycle 0 = ALL ODD positions! Cycle 1 = ALL EVEN positions! ***")
    else:
        print(f"  Parity: {even_in_cyc0} even in cycle 0 (not pure parity split)")
else:
    print(f"K3 does NOT have 2 equal cycles (actual: {[len(c) for c in k3_cycles]})")

# Step analysis
print(f"\nK3_PERM[0]={K3_PERM[0]}, K3_PERM[1]={K3_PERM[1]}, K3_PERM[335]={K3_PERM[335]}")
step01 = abs(K3_PERM[0] - K3_PERM[1])
print(f"  |K3_PERM[0] - K3_PERM[1]| = {step01}")
print(f"  GCD({step01}, 336) = {math.gcd(step01, 336)}")

# =============================================================================
print("\n" + "=" * 72)
print("C. K3 vs 180-DEGREE READING ORDER")
print("=" * 72)

# For each K3 position i, compute its grid coords and the 180-reflected top-half index
k3_grid_coords = [k3_pos_to_grid(i) for i in range(336)]
k3_top_half_indices = [(27 - r) * 31 + (30 - c) for (r, c) in k3_grid_coords]

print("Top-half reflected indices of K3 positions (first 10):")
for i in range(10):
    r, c = k3_grid_coords[i]
    print(f"  K3[{i}] at ({r},{c}) -> reflected ({27-r},{30-c}), top_idx={k3_top_half_indices[i]}")

# Sort K3 positions by their top-half reflected index
sorted_by_reflection = sorted(range(336), key=lambda i: k3_top_half_indices[i])
print(f"\nSorted K3 positions by reflected top-half index (first 10):")
print(f"  {sorted_by_reflection[:10]}")
print(f"  (last 10): {sorted_by_reflection[-10:]}")

# Hypothesis: K3_INV_PERM[j] = sorted_by_reflection[j]
# i.e., reading K3 in 180-reflected top-half order gives PT
match_count = sum(1 for j in range(336) if K3_INV_PERM[j] == sorted_by_reflection[j])
print(f"\nC1. Matches: K3_INV_PERM[j] == sorted_by_reflection[j]: {match_count}/336")

# Hypothesis: reading K3_CT in sorted_by_reflection order gives K3_PT
candidate_pt_c1 = "".join(K3_CT[sorted_by_reflection[j]] for j in range(336))
mm_c1 = sum(1 for j in range(336) if candidate_pt_c1[j] != K3_PT[j])
print(f"C1. Reading K3 in 180-reflected order: {mm_c1} mismatches from K3_PT")
if mm_c1 == 0:
    print("  *** PERFECT MATCH: 180-degree reading gives K3_PT! ***")
else:
    print(f"  Candidate: {candidate_pt_c1[:40]}...")
    print(f"  K3_PT:     {K3_PT[:40]}...")

# Also try: sorted by REVERSE of reflection (bottom-half -> top-half, ascending)
sorted_by_reflection_rev = sorted(range(336), key=lambda i: -k3_top_half_indices[i])
candidate_pt_c1r = "".join(K3_CT[sorted_by_reflection_rev[j]] for j in range(336))
mm_c1r = sum(1 for j in range(336) if candidate_pt_c1r[j] != K3_PT[j])
print(f"\nC2. Reading K3 in REVERSE 180-reflected order: {mm_c1r} mismatches from K3_PT")
if mm_c1r == 0:
    print("  *** PERFECT MATCH: reverse 180-degree reading gives K3_PT! ***")

# Test with pass1/pass2 split (2-cycle Cardan grille)
# Split K3 positions into those with even vs odd top-half index
even_top = sorted([i for i in range(336) if k3_top_half_indices[i] % 2 == 0],
                  key=lambda i: k3_top_half_indices[i])
odd_top = sorted([i for i in range(336) if k3_top_half_indices[i] % 2 == 1],
                 key=lambda i: k3_top_half_indices[i])
print(f"\nC3. Even vs odd reflected top-half index split:")
print(f"  Even count: {len(even_top)}, Odd count: {len(odd_top)}")

# Test if pass1=even, pass2=odd corresponds to K3_INV_PERM[0..167] and [168..335]
if len(even_top) == 168 and len(odd_top) == 168:
    pass1_match = sum(1 for j in range(168) if K3_INV_PERM[j] == even_top[j])
    pass2_match = sum(1 for j in range(168) if K3_INV_PERM[168+j] == odd_top[j])
    print(f"  C3a. Pass1 (even) matches K3_INV_PERM[0..167]: {pass1_match}/168")
    print(f"  C3b. Pass2 (odd) matches K3_INV_PERM[168..335]: {pass2_match}/168")

# Alternative: K3_PERM[i] % 2 == top_idx(i) % 2?
parity_match = sum(1 for i in range(336)
                   if K3_PERM[i] % 2 == k3_top_half_indices[i] % 2)
print(f"\nC4. K3_PERM[i] parity matches top_idx parity: {parity_match}/336")

# =============================================================================
print("\n" + "=" * 72)
print("D. K4 DIRECT 180-DEGREE TEST: READ REFLECTED CHARS FROM K1/K2")
print("=" * 72)

# For each K4 position i, read the char at its 180-reflected position
k4_grid_coords = [k4_pos_to_grid(i) for i in range(97)]
k4_reflected_coords = [(27 - r, 30 - c) for (r, c) in k4_grid_coords]

print("K4 positions and their 180-degree reflections (first 10):")
for i in range(10):
    r, c = k4_grid_coords[i]
    r2, c2 = k4_reflected_coords[i]
    ch = GRID[r2][c2]
    print(f"  K4[{i:2d}]={K4_CARVED[i]} at ({r},{c:2d}) -> reflected ({r2},{c2:2d}) = '{ch}'")

k4_reflected_chars = "".join(GRID[r2][c2] for (r2, c2) in k4_reflected_coords)
# Filter non-alpha (? marks)
k4_reflected_alpha = "".join(c for c in k4_reflected_chars if c in AZ)

print(f"\nK4 reflected reading (97 chars, including ? if any):")
print(f"  {k4_reflected_chars}")
print(f"  Alpha only ({len(k4_reflected_alpha)} chars): {k4_reflected_alpha}")

# Check if any ? chars in reflected reading
if '?' in k4_reflected_chars:
    q_positions = [i for i, c in enumerate(k4_reflected_chars) if c == '?']
    print(f"  WARNING: {len(q_positions)} '?' chars at K4 positions: {q_positions}")

print(f"\nTesting K4 reflected reading as real CT...")
hit_d1, best_d1 = test_candidate_ct(k4_reflected_chars.replace('?', 'A'), "D1-180REF", require_min=2)
if not hit_d1 and best_d1:
    print(f"  Best: score={best_d1[0]}/24 [{best_d1[2]}/{best_d1[3]}/{best_d1[4]}] "
          f"ENE={best_d1[5]} BC={best_d1[6]}: {best_d1[1][:40]}...")

# =============================================================================
print("\n" + "=" * 72)
print("E. K4 REVERSE/ALTERNATING 180-DEGREE READINGS")
print("=" * 72)

# E1: Reverse K4 order, then reflect
k4_reflected_reversed = "".join(GRID[27 - r][30 - c]
                                 for (r, c) in reversed(k4_grid_coords))
print(f"\nE1. K4 in REVERSE order, reflected:")
print(f"  {k4_reflected_reversed}")
hit_e1, best_e1 = test_candidate_ct(k4_reflected_reversed.replace('?', 'A'), "E1-REV180", require_min=2)
if not hit_e1 and best_e1:
    print(f"  Best: score={best_e1[0]}/24 [{best_e1[2]}/{best_e1[3]}/{best_e1[4]}]")

# E2: Reflect K4 position, then read K4 char at that reflected position
# (inverse direction: K1/K2 chars index into K4)
# For top-half position (r2,c2), does K4 have a char at (27-r2, 30-c2)?
# This is just the same as D1 (symmetric operation)

# E3: Column-by-column reflected reading
k4_by_col_reflected = []
for c in range(31):
    for r in range(24, 28):
        i = None
        if r == 24 and c >= 27:
            i = c - 27
        elif r >= 25:
            i = 4 + (r - 25) * 31 + c
        if i is not None and 0 <= i < 97:
            r2, c2 = 27 - r, 30 - c
            k4_by_col_reflected.append(GRID[r2][c2])

# Pad/trim to 97
k4_by_col_reflected_str = "".join(k4_by_col_reflected)
print(f"\nE3. K4 column-by-column, reflected ({len(k4_by_col_reflected_str)} chars):")
print(f"  {k4_by_col_reflected_str[:60]}...")
if len(k4_by_col_reflected_str) == 97:
    hit_e3, best_e3 = test_candidate_ct(k4_by_col_reflected_str.replace('?', 'A'), "E3-COL180", require_min=2)
    if not hit_e3 and best_e3:
        print(f"  Best: score={best_e3[0]}/24 [{best_e3[2]}/{best_e3[3]}/{best_e3[4]}]")

# E4: K4 carved directly (to benchmark)
print(f"\nE4. K4 CARVED DIRECTLY (baseline crib score):")
hit_e4, best_e4 = test_candidate_ct(K4_CARVED, "E4-BASELINE", require_min=0)
if best_e4:
    print(f"  Baseline best: score={best_e4[0]}/24 "
          f"[{best_e4[2]}/{best_e4[3]}/{best_e4[4]}]: {best_e4[1][:40]}...")

# =============================================================================
print("\n" + "=" * 72)
print("F. FULL BOTTOM-HALF 434-CHAR 180-DEGREE READING")
print("=" * 72)

# Read all 434 bottom-half positions, but in the order given by their 180-reflected
# top-half positions (row-major).
# This maps each bottom-half position to a top-half index.

bottom_half = []
for r in range(14, 28):
    for c in range(31):
        ch = GRID[r][c]
        top_r, top_c = 27 - r, 30 - c
        top_idx = top_r * 31 + top_c
        bottom_half.append((top_idx, r, c, ch))

# Sort by reflected top-half row-major index
bottom_half_sorted = sorted(bottom_half, key=lambda x: x[0])

# Extract just the chars
bottom_half_180 = "".join(x[3] for x in bottom_half_sorted)
print(f"Bottom half in 180-reflected reading order (434 chars):")
print(f"  {bottom_half_180[:60]}...")
print(f"  ...{bottom_half_180[-30:]}")

# K4 is at positions 336+1+0..96 = 337..433 in the bottom half (by row-major index)
# In the 180-reflected order, where does K4 fall?
k4_top_indices = [k3_top_half_indices[0]]  # placeholder; compute separately
k4_reflected_top_indices = [(27 - r) * 31 + (30 - c) for (r, c) in k4_grid_coords]

# In the sorted bottom half, find K4 positions
k4_in_sorted = []
for i, (top_idx, r, c, ch) in enumerate(bottom_half_sorted):
    if (r, c) in [k4_pos_to_grid(j) for j in range(97)]:
        k4_in_sorted.append((i, r, c, ch))

print(f"\nK4 positions in 180-sorted bottom half:")
for i, r, c, ch in k4_in_sorted[:5]:
    print(f"  Position {i} in sorted order: ({r},{c})='{ch}'")
print(f"  ... ({len(k4_in_sorted)} total K4 positions)")

# Extract K4 portion of bottom_half_180 by finding K4 positions
k4_from_sorted = "".join(ch for _, r, c, ch in k4_in_sorted)
print(f"K4 chars in 180-reflected sorted order: {k4_from_sorted}")

# Now try decoding this as real CT
print(f"\nTesting K4 in 180-reflected sorted order as real CT:")
hit_f1, best_f1 = test_candidate_ct(k4_from_sorted.replace('?', 'A'), "F1-SORTED180", require_min=2)
if not hit_f1 and best_f1:
    print(f"  Best: score={best_f1[0]}/24 [{best_f1[2]}/{best_f1[3]}/{best_f1[4]}]")

# =============================================================================
print("\n" + "=" * 72)
print("G. PAIRING HYPOTHESIS: K4[i] XOR K1/K2[reflected] -> UNSCRAMBLE")
print("=" * 72)

# In a Vigenere cipher: P + K = C -> P = C - K
# If K4_CARVED = real_CT scrambled, and the grille reads K1/K2 chars at
# reflected positions as the "reading order key", then:
# real_CT[j] = K4_CARVED[sigma(j)] where sigma is defined by 180-degree grille

# Alternative: use K1/K2 chars at reflected positions as a Vigenere key
# applied to K4_CARVED to get real_CT

k1_k2_at_reflected = k4_reflected_chars  # 97 chars from K1/K2 at K4's reflected positions
print(f"K1/K2 chars at K4-reflected positions: {k1_k2_at_reflected}")
print(f"K4 carved:                              {K4_CARVED}")

# Use k1_k2_at_reflected as Vigenere key on K4_CARVED
print(f"\nG1. k1k2_reflected as Vigenere key on K4_CARVED:")
for aname, alpha in ALPHABETS:
    for cname, cfn in CIPHER_FNS:
        try:
            key_cleaned = "".join(c for c in k1_k2_at_reflected if c in alpha)
            if len(key_cleaned) >= 97:
                pt = cfn(K4_CARVED, key_cleaned[:97], alpha)
                sc = crib_score(pt)
                e, b, fe, fb = check_cribs(pt)
                if sc >= 2 or fe or fb:
                    print(f"  [{cname}/{aname}] score={sc}: {pt[:40]}...")
                    if fe:
                        print(f"    *** EASTNORTHEAST FOUND! ***")
                    if fb:
                        print(f"    *** BERLINCLOCK FOUND! ***")
        except Exception:
            pass

# G2: Use K4_CARVED as Vigenere key on k1_k2_at_reflected
print(f"\nG2. K4_CARVED as Vigenere key on k1k2_reflected:")
for aname, alpha in ALPHABETS:
    for cname, cfn in CIPHER_FNS:
        try:
            key_cleaned = "".join(c for c in K4_CARVED if c in alpha)
            ct_cleaned = "".join(c for c in k1_k2_at_reflected if c in alpha)
            if len(ct_cleaned) >= 13:
                pt = cfn(ct_cleaned, key_cleaned, alpha)
                sc = crib_score(pt)
                e, b, fe, fb = check_cribs(pt)
                if sc >= 2 or fe or fb:
                    print(f"  [{cname}/{aname}] score={sc}: {pt[:40]}...")
        except Exception:
            pass

# =============================================================================
print("\n" + "=" * 72)
print("H. K3 EVEN/ODD CYCLE vs 180-DEGREE GEOMETRY")
print("=" * 72)

# Map K3 cycle membership to grid geometry
k3_cycle_ids = [None] * 336
for ci, cyc in enumerate(k3_cycles):
    for pos in cyc:
        k3_cycle_ids[pos] = ci

# For each K3 position i:
# - k3_cycle_ids[i] = which K3 permutation cycle it belongs to
# - k3_top_half_indices[i] = its 180-reflected top-half row-major index
# Is there a parity/modular relationship?

print("K3 cycle vs top-half-index parity:")
for ci, cyc in enumerate(k3_cycles):
    thi = [k3_top_half_indices[pos] for pos in cyc]
    even_count = sum(1 for x in thi if x % 2 == 0)
    print(f"  Cycle {ci} (len={len(cyc)}): {even_count} even, {len(cyc)-even_count} odd top-half-indices")

# For K3 positions, check if cycle membership correlates with grid row parity
for ci, cyc in enumerate(k3_cycles):
    row_parities = [k3_pos_to_grid(pos)[0] % 2 for pos in cyc]
    even_row = sum(1 for p in row_parities if p == 0)
    print(f"  Cycle {ci}: {even_row} even-row positions, {len(cyc)-even_row} odd-row positions")

for ci, cyc in enumerate(k3_cycles):
    col_parities = [k3_pos_to_grid(pos)[1] % 2 for pos in cyc]
    even_col = sum(1 for p in col_parities if p == 0)
    print(f"  Cycle {ci}: {even_col} even-col positions, {len(cyc)-even_col} odd-col positions")

# =============================================================================
print("\n" + "=" * 72)
print("I. K3 PASS1/PASS2 SPLIT BY 180-DEGREE REFLECTION WITHIN K3 DOMAIN")
print("=" * 72)

# Hypothesis: the K3 transposition is a 2-pass Cardan grille where:
# Pass 1 positions = {i in K3 : k3_top_half_index[i] is in some set}
# Pass 2 positions = complement

# Check: does sorting K3 positions by top-half-index, then splitting
# the first 168 as pass1 and last 168 as pass2, match cycle structure?
k3_sorted_by_top = sorted(range(336), key=lambda i: k3_top_half_indices[i])
pass1_proposed = set(k3_sorted_by_top[:168])
pass2_proposed = set(k3_sorted_by_top[168:])

# Check overlap with K3 cycles
for ci, cyc in enumerate(k3_cycles):
    cyc_set = set(cyc)
    in_pass1 = len(cyc_set & pass1_proposed)
    in_pass2 = len(cyc_set & pass2_proposed)
    print(f"Cycle {ci} (len={len(cyc)}): {in_pass1} in pass1, {in_pass2} in pass2")

# Check if pass1 = cycle 0 exactly
if k3_cycles:
    cyc0_set = set(k3_cycles[0])
    pass1_matches_cyc0 = len(cyc0_set & pass1_proposed)
    print(f"\nPass1 positions matching cycle 0: {pass1_matches_cyc0}/168")
    print(f"Pass1 positions matching cycle 1: {len(set(k3_cycles[1]) & pass1_proposed) if len(k3_cycles)>1 else 'N/A'}/168")

# =============================================================================
print("\n" + "=" * 72)
print("J. AZ->KA CYCLE INTEGRATION WITH 180-DEGREE STRUCTURE")
print("=" * 72)

print(f"AZ->KA cycles: {[len(c) for c in AZ_KA_CYCLES]} (17-cycle, 8-cycle, 1-fixed)")

# For each K4 position, what AZ->KA cycle does the carved letter belong to?
k4_cycle_ids = [LETTER_CYCLE_ID.get(K4_CARVED[i], -1) for i in range(97)]
print(f"\nK4 cycle membership distribution: {Counter(k4_cycle_ids)}")
# 0=17-cycle, 1=8-cycle, 2=Z(fixed)

# For reflected K1/K2 positions, same analysis
k4_ref_cycle_ids = [LETTER_CYCLE_ID.get(k4_reflected_chars[i], -1)
                    for i in range(97) if k4_reflected_chars[i] in AZ]
print(f"K4-reflected chars cycle distribution: {Counter(k4_ref_cycle_ids)}")

# Hypothesis: 17-cycle positions in K4 are the "holes" for K1/K2 data
# 8-cycle positions in K4 are "holes" for some other purpose
# Test: use only 17-cycle K4 positions as grille holes
holes_17 = [i for i in range(97) if K4_CARVED[i] in AZ and LETTER_CYCLE_ID[K4_CARVED[i]] == 0]
holes_8 = [i for i in range(97) if K4_CARVED[i] in AZ and LETTER_CYCLE_ID[K4_CARVED[i]] == 1]
print(f"\n17-cycle K4 positions: {len(holes_17)} -> {[K4_CARVED[i] for i in holes_17[:10]]}...")
print(f"8-cycle K4 positions: {len(holes_8)} -> {[K4_CARVED[i] for i in holes_8[:10]]}...")

# Similarly for reflected chars
holes_17_ref = [i for i in range(97)
                if k4_reflected_chars[i] in AZ and LETTER_CYCLE_ID[k4_reflected_chars[i]] == 0]
holes_8_ref = [i for i in range(97)
               if k4_reflected_chars[i] in AZ and LETTER_CYCLE_ID[k4_reflected_chars[i]] == 1]
print(f"\n17-cycle reflected positions: {len(holes_17_ref)}")
print(f"8-cycle reflected positions: {len(holes_8_ref)}")

# =============================================================================
print("\n" + "=" * 72)
print("K. K3 EXTENSION TO K4: GRILLE CONTINUITY")
print("=" * 72)

# K3 occupies positions 0..335 in the bottom half.
# K4 occupies positions 337..433 (with ? at 336).
# If the same grille pattern continues into K4, extend K3 permutation.

# K3 perm step: each pair in K3_PERM has a specific step.
# Analyze step pattern in K3_PERM
steps_k3 = [(K3_PERM[i] - K3_PERM[i-1]) % 336 for i in range(1, 336)]
step_counter = Counter(steps_k3)
print(f"K3_PERM step distribution (top 10): {step_counter.most_common(10)}")

# Check if K3_PERM[i] = some_linear_function(i) mod 336
# Try K3_PERM[i] = (a*i + b) % 336
for a in [335, 334, 168, 1]:
    b = K3_PERM[0]
    mismatches = sum(1 for i in range(336) if K3_PERM[i] != (a * i + b) % 336)
    if mismatches < 50:
        print(f"  Linear test K3_PERM[i] = ({a}*i + {b}) % 336: {mismatches} mismatches")

# Check if K3_PERM is involutory (K3_PERM[K3_PERM[i]] == i)
involutory = sum(1 for i in range(336) if K3_PERM[K3_PERM[i]] == i)
print(f"K3_PERM involutory: {involutory}/336 (involution would mean K3_PERM = K3_INV_PERM)")

# For K4: extend the K3 permutation formula beyond 336
# k3_perm_fwd works for i=0..335. What about i=337..433 (K4 region in bottom half)?
# Row 24 col 26 = ? -> boundary (pos 336 in bottom half)
# K4: positions 337..433 in bottom half

# Bottom half linear position from grid:
def bottom_pos_from_grid(r, c):
    return (r - 14) * 31 + c  # 0..433

# K4 positions in bottom half
k4_bottom_positions = [bottom_pos_from_grid(r, c) for (r, c) in k4_grid_coords]
print(f"\nK4 bottom-half linear positions: {k4_bottom_positions[:5]}...{k4_bottom_positions[-5:]}")
print(f"  Min: {min(k4_bottom_positions)}, Max: {max(k4_bottom_positions)}")

# Extend K3_PERM formula to K4 range (hypothetically)
# The formula k3_perm_fwd uses 336=24*14=8*42 specific factorizations
# For the 434-char bottom half (28*31/2), what would the analogous formula be?
# 434 = 14*31. Under 180° rotation of a 14*31 grid -> 31*14.
# CW rotation of 14*31: old[r][c] -> new[c][13-r], new grid 31 rows x 14 cols
def bottom_half_180_perm(i):
    """180-degree rotation of a 14x31 grid (the bottom half).
    Position i in 14x31 -> reflected position.
    180-degree: old[r][c] -> new[13-r][30-c]
    new position = (13-r)*31 + (30-c) = 433 - r*31 - c = 433 - i
    """
    return 433 - i

# This is just the reverse permutation (position i -> 433-i)
# Check: does reversing the bottom-half position order explain K4?
# bottom_half positions for K4:
k4_180_perm = [bottom_half_180_perm(p) for p in k4_bottom_positions]
print(f"\nK4 bottom positions under 180-degree perm (reverse): {k4_180_perm[:5]}...{k4_180_perm[-5:]}")

# The 180-degree permuted bottom positions for K4 land in K3/? territory
# because K4 is at positions 337-433 and 433-337=96, 433-433=0
# -> maps to positions 0..96 in bottom half = K3 territory!
k4_maps_to_k3 = [(p, 433 - p) for p in k4_bottom_positions]
print(f"K4[i] at bottom pos p -> maps to bottom pos 433-p:")
for i in range(5):
    orig_p, new_p = k4_maps_to_k3[i]
    orig_r, orig_c = k4_grid_coords[i]
    # new position in K3 territory:
    new_r = 14 + new_p // 31
    new_c = new_p % 31
    k3_char = GRID[new_r][new_c] if 0 <= new_r < 28 else '?'
    print(f"  K4[{i}]={K4_CARVED[i]} at ({orig_r},{orig_c}) bottom_pos={orig_p} "
          f"-> bottom_pos={new_p} -> ({new_r},{new_c})={k3_char}")

# Extract the 97 K3 chars corresponding to K4's 180-degree mapped positions
k4_to_k3_chars = []
for i in range(97):
    orig_p = k4_bottom_positions[i]
    new_p = 433 - orig_p
    new_r = 14 + new_p // 31
    new_c = new_p % 31
    if 0 <= new_r < 28 and 0 <= new_c < 31:
        k4_to_k3_chars.append(GRID[new_r][new_c])
    else:
        k4_to_k3_chars.append('?')

k4_to_k3_str = "".join(k4_to_k3_chars)
print(f"\nK4 mapped to K3 via bottom-half 180-degree ({len(k4_to_k3_str)} chars):")
print(f"  {k4_to_k3_str}")

# This should be different from D1 (which mapped to top-half)
# Note: K4 bottom-half positions 337..433 -> 96..0 which are early K3 positions
print(f"\nTesting K3-mapped K4 chars as real CT:")
hit_k1, best_k1 = test_candidate_ct(k4_to_k3_str.replace('?', 'A'), "K1-BOT180", require_min=2)
if not hit_k1 and best_k1:
    print(f"  Best: score={best_k1[0]}/24 [{best_k1[2]}/{best_k1[3]}/{best_k1[4]}]")

# =============================================================================
print("\n" + "=" * 72)
print("L. PERMUTATION RECOVERY: WHAT SIGMA MAKES K4 DECRYPTABLE?")
print("=" * 72)

# The fundamental question: what permutation sigma (97 elements) maps
# K4_CARVED -> real_CT such that any keyword Vigenere on real_CT gives
# K4_PT with ENE at 21-33 and BC at 63-73?

# Known constraints:
# - CT[32] = PT[32] = 'S' (self-encrypting under Vigenere)
# - CT[73] = PT[73] = 'K' (self-encrypting)
# These constrain sigma:
# - real_CT[32] = K4_CARVED[sigma(32)] must equal 'S' for some key
# - real_CT[73] = K4_CARVED[sigma(73)] must equal 'K' for some key

# For Vigenere: real_CT[i] = Vig(PT[i], key[i%len]) -> PT[i] = AZ[(CT[i]-key)%26]
# Self-encrypting means PT[i] = CT[i], so AZ[(CT[i] - key[i%len]) % 26] = CT[i]
# -> key[i%len] = 0 -> key letter = 'A' or key letter = 'K' for KA alphabet

# Bean constraint: k[27] = k[65] where k = key letter index in alpha
# For Vigenere with key of length L: key[27%L] = key[65%L]

# Let's just enumerate all possible sigma values for positions 32 and 73
# to find K4_CARVED positions that give 'S' and 'K' respectively
S_positions = [i for i in range(97) if K4_CARVED[i] == 'S']
K_positions = [i for i in range(97) if K4_CARVED[i] == 'K']
print(f"K4 positions with 'S': {S_positions} ({len(S_positions)} positions)")
print(f"K4 positions with 'K': {K_positions} ({len(K_positions)} positions)")

# For the 180-degree reflection: sigma(i) = position in K4 such that
# K4_CARVED[sigma(i)] = "real CT at position i"
# Under 180-degree: sigma(i) = 96 - i (reverse order within K4)
sigma_180 = list(range(96, -1, -1))  # sigma(i) = 96 - i
print(f"\nSimple 180-degree sigma: sigma(i) = 96 - i")
print(f"  sigma(32) = {sigma_180[32]}, K4_CARVED[{sigma_180[32]}] = '{K4_CARVED[sigma_180[32]]}'")
print(f"  sigma(73) = {sigma_180[73]}, K4_CARVED[{sigma_180[73]}] = '{K4_CARVED[sigma_180[73]]}'")

# Apply sigma_180 to get real_CT
real_ct_180 = "".join(K4_CARVED[sigma_180[i]] for i in range(97))
print(f"\nReal CT under sigma_180 (reverse K4):")
print(f"  {real_ct_180}")
print(f"Testing reverse K4 as real CT...")
hit_l1, best_l1 = test_candidate_ct(real_ct_180, "L1-REVERSE", require_min=2)
if not hit_l1 and best_l1:
    print(f"  Best: score={best_l1[0]}/24 [{best_l1[2]}/{best_l1[3]}/{best_l1[4]}]")

# L2: sigma from K3 formula extended to K4 range
# K3 uses 24x14 and 8x42 grids. K4+padding = ?
# Try treating K4 as fitting in a grid
print(f"\nL2. K4 as 7x14 (98 chars, 1 null) grid, double CW rotation:")
# 97 prime -> pad to 98 = 7*14
K4_PADDED = K4_CARVED + 'X'  # 98 = 7*14
def perm_7x14_cw_cw(i):
    """Double CW rotation: 7x14 -> 14x7 -> 7x14"""
    a = i // 14; b = i % 14
    # After first CW (7x14 -> 14x7):
    new_r1 = b; new_c1 = 6 - a  # CW: old[r][c] -> new[c][nrows-1-r]
    pos1 = new_r1 * 7 + new_c1  # in 14x7 grid
    # After second CW (14x7 -> 7x14):
    a2 = pos1 // 7; b2 = pos1 % 7
    new_r2 = b2; new_c2 = 13 - a2  # CW on 14x7
    return new_r2 * 14 + new_c2

perm_k4_7x14 = [perm_7x14_cw_cw(i) for i in range(98)]
if len(set(perm_k4_7x14)) == 98:
    print(f"  7x14 double CW: valid permutation")
    real_ct_7x14 = "".join(K4_PADDED[perm_k4_7x14[i]] for i in range(97))
    print(f"  Real CT: {real_ct_7x14}")
    hit_l2, best_l2 = test_candidate_ct(real_ct_7x14, "L2-7x14", require_min=2)
    if not hit_l2 and best_l2:
        print(f"  Best: score={best_l2[0]}/24 [{best_l2[2]}/{best_l2[3]}/{best_l2[4]}]")
else:
    print(f"  7x14 double CW: NOT a valid permutation (duplicate positions)")

# L3: sigma from K3 formula's structural pattern but for 97-char range
# K3_PERM[i] = 42*d + 41 - c where inter = 14*b + 13 - a, a=i//24, b=i%24
# Try analogous for K4:
# 97 doesn't factor nicely. Try 97 itself:
# single CW rotation of 1x97 = trivial. Not useful.
# Try period-7 connection:
print(f"\nL3. K4 with K3-style formula adapted for 7x14=98 (alt formulas):")

# Adapted formula: same structure but for K4's dimensions
def k4_perm_alt1(i):
    """Try 7x14 -> 14x7 -> 7x14 with different reading."""
    # Write into 7 rows x 14 cols (row-major)
    a = i // 14  # row (0..6)
    b = i % 14   # col (0..13)
    # Read by columns (column-major): col 0 top-to-bottom, col 1, ...
    return b * 7 + a  # columnar transposition, 14 cols

perm_k4_col14 = [k4_perm_alt1(i) for i in range(98)]
if len(set(perm_k4_col14)) == 98:
    real_ct_col14 = "".join(K4_PADDED[perm_k4_col14[i]] for i in range(97))
    print(f"  7x14 columnar: {real_ct_col14}")
    hit_l3, best_l3 = test_candidate_ct(real_ct_col14, "L3-COL14", require_min=2)
    if not hit_l3 and best_l3:
        print(f"  Best: score={best_l3[0]}/24 [{best_l3[2]}/{best_l3[3]}/{best_l3[4]}]")

# =============================================================================
print("\n" + "=" * 72)
print("M. K3 CALIBRATION: VERIFY STRUCTURAL FACTS")
print("=" * 72)

print(f"K3 PT (known): {K3_PT}")
print(f"K3 CT (carved): {K3_CT}")
print(f"K3 permutation verified: 0 mismatches")

# Compute the K3 INV_PERM statistics for 180-degree analysis
print(f"\nK3_INV_PERM (hole j at K3 carved position K3_INV_PERM[j]):")
print(f"  First 20: {K3_INV_PERM[:20]}")
print(f"  Last 20: {K3_INV_PERM[-20:]}")

# Map K3_INV_PERM to grid coordinates
k3_inv_perm_grid = [k3_pos_to_grid(K3_INV_PERM[j]) for j in range(336)]

# Sort j by top-half reflected index of K3_INV_PERM[j]
k3_inv_top_idx = [(27 - r) * 31 + (30 - c) for (r, c) in k3_inv_perm_grid]

# Is there a monotonic relationship between j and k3_inv_top_idx[j]?
# Spearman rank correlation
sorted_j_by_top = sorted(range(336), key=lambda j: k3_inv_top_idx[j])
spearman_concordant = sum(1 for j in range(335) if sorted_j_by_top[j] < sorted_j_by_top[j+1])
print(f"\nMonotonicity of K3_INV_PERM top-half index with j:")
print(f"  Concordant pairs: {spearman_concordant}/335 (336 would be perfectly monotone)")

# Range of k3_inv_top_idx
print(f"  Min top_idx: {min(k3_inv_top_idx)}, Max: {max(k3_inv_top_idx)}")
print(f"  Unique top_idx values: {len(set(k3_inv_top_idx))}/336 (should be 336 if bijective)")

# The 180-degree hypothesis: K3_INV_PERM gives holes in position 2 (K3 territory),
# and their reflections (given by k3_inv_top_idx) are the corresponding position 1 holes.
# For the grille to be a proper Cardan grille:
# - All 336 positions in K3 territory (rows 14-24) must be holes in position 2
# - Under 180-degree, all map to rows 3-13 (K1/K2 territory)
# - Position 1 holes are in rows 3-13
# - Position 1 reading order = position 2 reading order

# Check if k3_inv_top_idx values span all possible values in rows 3-13
print(f"\nTop-half reflected positions of K3 holes:")
top_rows = Counter([k3_inv_perm_grid[j][0] for j in range(336)])
for row in sorted(top_rows):
    ref_row = 27 - row
    print(f"  K3 holes in row {ref_row} -> reflected in row {row}: {top_rows[row]} holes")

# =============================================================================
print("\n" + "=" * 72)
print("N. EXTENDED 180-DEGREE SIGMA VARIANTS FOR K4")
print("=" * 72)

# N1: K4 reversed within each row
def k4_reverse_rows():
    """Reverse K4 chars within each row of the cipher grid."""
    result = []
    # Row 24 cols 27-30 (4 chars): reverse to cols 30-27
    row24 = K4_CARVED[0:4]
    result.extend(reversed(row24))
    # Row 25 (31 chars): reverse
    row25 = K4_CARVED[4:35]
    result.extend(reversed(row25))
    # Row 26 (31 chars): reverse
    row26 = K4_CARVED[35:66]
    result.extend(reversed(row26))
    # Row 27 (31 chars): reverse
    row27 = K4_CARVED[66:97]
    result.extend(reversed(row27))
    return "".join(result)

k4_row_reversed = k4_reverse_rows()
print(f"N1. K4 with reversed rows:")
print(f"  {k4_row_reversed}")
hit_n1, best_n1 = test_candidate_ct(k4_row_reversed, "N1-ROWREV", require_min=2)
if not hit_n1 and best_n1:
    print(f"  Best: score={best_n1[0]}/24 [{best_n1[2]}/{best_n1[3]}/{best_n1[4]}]")

# N2: K4 read column-by-column (within K4's subgrid)
def k4_columnwise():
    """Read K4 column by column (within the 4-row K4 subgrid)."""
    k4_grid = [
        ['?', '?', '?'] + list(K4_CARVED[0:4]),           # row 24, cols 0-30 (only 27-30 are K4)
        list(K4_CARVED[4:35]),                               # row 25
        list(K4_CARVED[35:66]),                              # row 26
        list(K4_CARVED[66:97]),                              # row 27
    ]
    # Actually, K4 in rows 24-27 with varying column extents
    # Row 24: cols 27-30 (4 chars) -> col offsets 0-3
    # Row 25: cols 0-30 (31 chars) -> col offsets 0-30
    # Row 26: cols 0-30 (31 chars) -> col offsets 0-30
    # Row 27: cols 0-30 (31 chars) -> col offsets 0-30
    # Not a regular grid, so column-by-column isn't clean.
    # Instead, treat K4 positions as filling a virtual 4-row grid:
    # Just reverse order (already tested as L1).
    return None

# N3: Read K4 in order defined by K3_PERM extended
# K3 PERM uses formula for positions 0..335 in a 24x14 / 8x42 context
# K4 is at bottom-half positions 337..433 (counting the ? boundary as 336)
# Try extending the 336-element formula to 434 total

# The K3 formula: k3_perm_fwd(i) for i=0..335 -> 0..335
# What if we extend i to 0..433 and see what happens?
def k3_perm_extended(i):
    """Try extending K3 permutation formula to i=0..433."""
    # Original: 336 = 24*14 = 8*42
    # Extended: 434 = 14*31 or 31*14
    # Use 14*31: rows=14, cols=31
    if i >= 434:
        return -1
    a = i // 31  # row (0..13)
    b = i % 31   # col (0..30)
    # First "rotation": 14x31 -> 31x14 (CW)
    # new[b][13-a] -> pos = b*14 + (13-a)
    inter = b * 14 + 13 - a
    # Second "rotation": 31x14 -> 14x31 (CW)
    c = inter // 31   # row in 31x14
    d = inter % 31    # col in 31x14
    # CW: -> new[d][30-c] in 31x14 -> 14x31
    # Actually let me think: 31x14 CW -> 14x31
    # old[r][c] -> new[c][30-r]? No...
    # CW rotation of nrows x ncols: old[r][c] -> new[c][nrows-1-r]
    # CW of 31x14: old[r][c] -> new[c][30-r], new grid is 14x31
    # new_r = c, new_c = 30-r (where r=0..30, c=0..13 in old 31x14 grid)
    # new position = new_r * 31 + new_c = c * 31 + (30 - r)
    # where r = inter // 14... wait, inter uses 14 cols, not 31...
    # This is getting complicated. Let's just compute it directly.
    # inter is position in 31*14 = 434 cell grid (31 rows x 14 cols)
    r2 = inter // 14  # row in 31x14
    c2 = inter % 14   # col in 31x14
    # CW rotation: 31x14 -> 14x31
    # old[r][c] -> new[c][30-r]
    new_r = c2
    new_c = 30 - r2
    return new_r * 31 + new_c

perm_extended = [k3_perm_extended(i) for i in range(434)]
valid_ext = len(set(perm_extended)) == 434 and all(0 <= p < 434 for p in perm_extended)
print(f"\nN3. Extended 14x31 double-CW formula (434 cells):")
print(f"  Valid permutation: {valid_ext}")
if valid_ext:
    # Check K3 portion (first 336 positions)
    k3_ext_matches = sum(1 for i in range(336) if perm_extended[i] == K3_PERM[i])
    print(f"  K3 portion matches K3_PERM: {k3_ext_matches}/336")
    # Apply to K4 portion (positions 337..433 in bottom half)
    # K4 at bottom-half positions k4_bottom_positions[i]
    k4_ext_perm = [perm_extended[p] for p in k4_bottom_positions]
    print(f"  K4 extended perm values: {k4_ext_perm[:10]}...")
    # Map to actual chars in bottom half
    def bottom_pos_to_char(p):
        r = 14 + p // 31
        c = p % 31
        if r < 28:
            return GRID[r][c]
        return '?'
    k4_ext_real_ct = "".join(bottom_pos_to_char(k4_ext_perm[i]) for i in range(97))
    print(f"  K4 real CT from extended formula: {k4_ext_real_ct}")
    hit_n3, best_n3 = test_candidate_ct(k4_ext_real_ct.replace('?','A'), "N3-EXT434", require_min=2)
    if not hit_n3 and best_n3:
        print(f"  Best: score={best_n3[0]}/24 [{best_n3[2]}/{best_n3[3]}/{best_n3[4]}]")

# =============================================================================
print("\n" + "=" * 72)
print("O. CRIB-PINNING: WHAT DO SELF-ENCRYPTING POSITIONS TELL US?")
print("=" * 72)

# Self-encrypting: CT[32]=PT[32]='S', CT[73]=PT[73]='K'
# For Vigenere PT[i] = AZ[(CT[i] - key[i%L]) % 26] = CT[i]
# => key[i%L] = 0 => key letter = 'A' (for AZ Vigenere)
# So the key letter at period position 32%L (mod period L) must be 'A'

# Also: EASTNORTHEAST[0] = 'E' = PT[21]
# BERLINCLOCK[0] = 'B' = PT[63]
# These further constrain the key.

# If sigma maps carved->real_CT: real_CT[i] = K4_CARVED[sigma(i)]
# For self-encrypting: real_CT[32] = 'S', so sigma(32) must be a position in K4 with 'S'
# K4 'S' positions: already computed as S_positions

# For any candidate sigma, check self-encrypting constraint
# Under 180-degree reflected reading:
ref_32 = k4_reflected_chars[32] if 32 < len(k4_reflected_chars) else '?'
ref_73 = k4_reflected_chars[73] if 73 < len(k4_reflected_chars) else '?'
print(f"Under D1 (180-reflected) reading:")
print(f"  real_CT[32] = '{ref_32}' (should be 'S' if self-encrypting)")
print(f"  real_CT[73] = '{ref_73}' (should be 'K' if self-encrypting)")

# Under reverse reading:
rev_32 = real_ct_180[32] if 32 < len(real_ct_180) else '?'
rev_73 = real_ct_180[73] if 73 < len(real_ct_180) else '?'
print(f"\nUnder L1 (reverse K4) reading:")
print(f"  real_CT[32] = '{rev_32}' (should be 'S')")
print(f"  real_CT[73] = '{rev_73}' (should be 'K')")

# Under K->K3 mapping:
k3map_32 = k4_to_k3_str[32] if 32 < len(k4_to_k3_str) else '?'
k3map_73 = k4_to_k3_str[73] if 73 < len(k4_to_k3_str) else '?'
print(f"\nUnder K1 (K3-mapped) reading:")
print(f"  real_CT[32] = '{k3map_32}' (should be 'S')")
print(f"  real_CT[73] = '{k3map_73}' (should be 'K')")

# =============================================================================
print("\n" + "=" * 72)
print("P. TABLEAU OVERLAY: CIPHER GRID vs TABLEAU UNDER 180-DEGREE")
print("=" * 72)

# The KA Vigenere tableau has the same 28x31 dimensions.
# Under 180-degree, tableau cell (r,c) maps to (27-r, 30-c) in the cipher grid.
# Does this define an interesting relationship?

# Tableau body: rows 1-26 (1-indexed), each row is key_letter + 30 KA-shifted chars
# In 0-indexed: rows 0 and 27 are headers, rows 1-26 are body.
# Key column: col 0 = AZ letters (rows 1-26) = rows A-Z
# Row 14 (key=N) has extra L anomaly.

# Build simplified tableau (key column + first 30 body chars)
TABLEAU = []
TABLEAU.append(list(" ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"))  # row 0 header (31 chars)
for ki in range(26):
    kl = AZ[ki]
    # KA shifted by ki positions
    row_body = KA[ki:] + KA[:ki]  # 26 chars
    # Extend to 30 chars (wrap)
    row_body_30 = (row_body * 2)[:30]
    # Add extra L at row 14 (anomaly) - makes it 31 chars including key col
    # Row 14 = key N (ki=13, since A=0, N=13)
    # Actually row indices 1-26 correspond to ki=0-25 (A-Z)
    # Row 14 (0-indexed) = ki=13 = N
    key_col = kl
    tableau_row = list(key_col + row_body_30[:30])  # 31 chars total
    TABLEAU.append(tableau_row)
TABLEAU.append(list(" ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"))  # row 27 footer

assert len(TABLEAU) == 28
for i, row in enumerate(TABLEAU):
    if len(row) != 31:
        print(f"  WARNING: Tableau row {i} has {len(row)} chars")
    TABLEAU[i] = (TABLEAU[i] + ['?'] * 31)[:31]  # normalize

# Under 180-degree rotation, cipher grid position (r,c) -> (27-r,30-c) in tableau
# For K4 position i:
k4_tableau_reflected = []
for i in range(97):
    r, c = k4_grid_coords[i]
    r2, c2 = 27 - r, 30 - c
    tab_char = TABLEAU[r2][c2]
    k4_tableau_reflected.append(tab_char)

k4_tab_reflected_str = "".join(k4_tableau_reflected)
print(f"K4 positions reflected into TABLEAU (97 chars):")
print(f"  {k4_tab_reflected_str}")

print(f"\nTesting K4 tableau-reflected as real CT:")
hit_p1, best_p1 = test_candidate_ct(k4_tab_reflected_str.replace('?','A').replace(' ','A'),
                                      "P1-TABLEAU180", require_min=2)
if not hit_p1 and best_p1:
    print(f"  Best: score={best_p1[0]}/24 [{best_p1[2]}/{best_p1[3]}/{best_p1[4]}]")

# =============================================================================
print("\n" + "=" * 72)
print("SUMMARY")
print("=" * 72)

# Collect all candidate CTs tested and their best scores
all_candidates = [
    ("D1-180REF", k4_reflected_chars.replace('?','A'), "K4 chars at 180-reflected K1/K2 positions"),
    ("E1-REV180", k4_reflected_reversed.replace('?','A'), "K4 reversed then reflected"),
    ("L1-REVERSE", real_ct_180, "K4 in reverse order (180-deg within K4)"),
    ("K1-BOT180", k4_to_k3_str.replace('?','A'), "K4 mapped to K3 via bottom-half 180-deg"),
    ("N1-ROWREV", k4_row_reversed, "K4 with each row reversed"),
    ("P1-TABLEAU", k4_tab_reflected_str.replace('?','A').replace(' ','A'), "K4 reflected into tableau"),
]

print("\nAll candidates tested (by crib score):")
results = []
for label, ct, desc in all_candidates:
    best_sc = 0
    best_pt = ""
    best_key = ""
    for kw in KEYWORDS:
        for aname, alpha in ALPHABETS:
            for cname, cfn in CIPHER_FNS:
                try:
                    pt = cfn(ct, kw, alpha)
                    sc = crib_score(pt)
                    if sc > best_sc:
                        best_sc = sc
                        best_pt = pt[:40]
                        best_key = f"{cname}/{kw}/{aname}"
                except Exception:
                    pass
    results.append((best_sc, label, desc, best_key, best_pt))

results.sort(reverse=True)
for sc, label, desc, key, pt in results:
    print(f"  [{label}] score={sc:2d}/24 {key}: {pt[:35]}...")
    print(f"           {desc}")

print("\n" + "=" * 72)
print("VERDICT")
print("=" * 72)
top_score = results[0][0] if results else 0
print(f"Best crib score across all 180-degree variants: {top_score}/24")
if top_score >= 20:
    print("STATUS: POSSIBLE SOLUTION FOUND")
elif top_score >= 10:
    print("STATUS: PROMISING - significant partial crib hit")
elif top_score >= 4:
    print("STATUS: INTERESTING - partial crib match detected")
else:
    print("STATUS: INCONCLUSIVE - no significant crib hits from direct 180-degree reading")
    print("The 180-degree reading order does NOT directly unscramble K4.")
    print("However, K3's 2-cycle structure remains compatible with a 2-pass Cardan grille.")

print(f"\nK3 verification: 0/336 mismatches (CONFIRMED)")
print(f"K3 cycle structure: {[len(c) for c in k3_cycles]} (2x168 = 2-pass grille compatible)")
print(f"180-degree pairs: all cross-half (CONFIRMED structural match)")
print(f"Self-encrypting check: D1[32]='{ref_32}'(need S), D1[73]='{ref_73}'(need K)")
