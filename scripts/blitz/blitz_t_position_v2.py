#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_t_position_v2.py — Fresh T-position exploitation using verified mask.

KEY DIFFERENCE from prior campaign: The previous scripts used a mask where
0=HOLE (space-separated format). The authoritative prompt mask (1=HOLE,
verified 2026-03-03) has different hole positions. This script uses the
correct mask and discovers the correct tableau formula.

Approaches:
A. Find correct tableau formula → derive T-holes → test segment permutations
B. T-column sequence as period-26 substitution key (novel key XWVUTSRQPOENMLZBKDYAJIHGCF)
C. T-positions in K4 carved text (at positions 35,37,50,67,68,80) as landmarks
D. Grid overlay: K4 in width-W grid, grille holes define reading order
E. CSP: T-plaintext positions (24,28,33) → forced σ constraints under Vig/KRYPTOS
F. T-hole coordinates as direct numeric permutation values
G. Per-row T-gap encoding (holes before/after T give bit vector)
H. Hybrid: T-avoidance + crib constraints (tight CSP)
"""

import sys, os, json, math, itertools
from collections import defaultdict
sys.path.insert(0, 'scripts')
from kbot_harness import (
    test_perm, test_unscramble, score_text, score_text_per_char,
    has_cribs, vig_decrypt, beau_decrypt, vig_encrypt,
    apply_permutation, load_quadgrams,
    K4_CARVED, GRILLE_EXTRACT, AZ, KA, KEYWORDS, CRIBS,
)

N = 97
assert len(K4_CARVED) == N
GE = GRILLE_EXTRACT
assert len(GE) == 106
assert 'T' not in GE, "T should be absent!"

KA_IDX = {ch: i for i, ch in enumerate(KA)}
AZ_IDX = {ch: i for i, ch in enumerate(AZ)}

os.makedirs('results/blitz_t_v2', exist_ok=True)

print("="*60)
print("blitz_t_position_v2.py — Fresh analysis with verified mask")
print("="*60)

# ============================================================
# SECTION 0: Parse the verified authoritative mask (1=HOLE)
# ============================================================
print("\n=== SECTION 0: Parse mask (1=HOLE, verified 2026-03-03) ===")

# From the mission prompt — authoritative mask
# Row 0-indexed in code; physical rows 01-28 in prompt
# 1=HOLE, 0=SOLID, ~ = off-grid (stripped)
MASK_ROWS = [
    "000000001010100000000010000000001",   # row 0 (phys 01)
    "100000000010000001000100110000011",   # row 1 (phys 02)
    "000000000000001000000000000000011",   # row 2 (phys 03)
    "00000000000000000000100000010011",    # row 3 (phys 04, 32 cols)
    "00000001000000001000010000000011",    # row 4 (phys 05, 32 cols)
    "000000001000000000000000000000011",   # row 5 (phys 06)
    "100000000000000000000000000000011",   # row 6 (phys 07)
    "00000000000000000000000100000100",    # row 7 (phys 08, 32 cols)
    "0000000000000000000100000001000",     # row 8 (phys 09, 31 cols)
    "0000000000000000000000000000100",     # row 9 (phys 10, 31 cols)
    "000000001000000000000000000000",      # row 10 (phys 11, 30 cols)
    "00000110000000000000000000000100",    # row 11 (phys 12, 32 cols)
    "00000000000000100010000000000001",    # row 12 (phys 13, 32 cols)
    "00000000000100000000000000001000",    # row 13 (phys 14, 32 cols)
    "000110100001000000000000001000010",   # row 14 (phys 15)
    "00001010000000000000000001000001",    # row 15 (phys 16, 32 cols)
    "001001000010010000000000000100010",   # row 16 (phys 17)
    "00000000000100000000010000010001",    # row 17 (phys 18, 32 cols)
    "000000000000010001001000000010001",   # row 18 (phys 19)
    "00000000000000001001000000000100",    # row 19 (phys 20, 32 cols)
    "000000001100000010100100010001001",   # row 20 (phys 21)
    "000000000000000100001010100100011",   # row 21 (phys 22)
    "00000000100000000000100001100001",    # row 22 (phys 23, 32 cols)
    "100000000000000000001000001000010",   # row 23 (phys 24)
    "10000001000001000000100000000001",    # row 24 (phys 25, 32 cols)
    "000010000000000000010000100000011",   # row 25 (phys 26)
    "0000000000000000000100001000000011",  # row 26 (phys 27, cap at 33)
    "00000000000000100000001010000001",    # row 27 (phys 28, 32 cols)
]

all_holes = []
for r, row_str in enumerate(MASK_ROWS):
    for c, ch in enumerate(row_str[:33]):  # cap at 33 cols
        if ch == '1':
            all_holes.append((r, c))

print(f"Total 1s (holes) in mask: {len(all_holes)}")

# ============================================================
# SECTION 1: Find correct tableau formula
# ============================================================
print("\n=== SECTION 1: Tableau formula discovery ===")

def try_formula(name, cell_fn, holes=all_holes):
    """Test if a tableau formula gives GRILLE_EXTRACT from holes."""
    letters = []
    t_hits = []
    for (r, c) in holes:
        v = cell_fn(r, c)
        if v is not None:
            letters.append(v)
            if v == 'T':
                t_hits.append((r, c))
    s = ''.join(letters)
    # Try exact match and T-filtered match
    exact = (s == GE)
    # Filter T
    no_t = s.replace('T', '')
    t_filtered = (no_t[:106] == GE if len(no_t) >= 106 else False)
    # Find GE as subsequence of s (T's removed)
    print(f"  {name}: {len(letters)} letters, {len(t_hits)} T-hits, "
          f"exact={exact}, T-filtered={t_filtered}")
    if len(s) >= 10:
        print(f"    First 20: {s[:20]}  GE: {GE[:20]}")
    return exact, t_filtered, t_hits, letters

# Formula H4: cell = KA[(r+c)%26] (rows/cols in KA order)
print("H4 (rows=KA, cols=KA, cell=KA[(r+c)%26]):")
exact_h4, tf_h4, t_hits_h4, letters_h4 = try_formula(
    "H4_k0",
    lambda r, c: KA[(r+c)%26] if (0<=r<=27 and 0<=c<=32) else None
)

# H4 with various column offsets
for ko in range(1, 8):
    exact, tf, th, lts = try_formula(
        f"H4_koff{ko}",
        lambda r, c, k=ko: KA[(r + c - k)%26] if (0<=r<=27 and k<=c<=k+25) else None
    )

# H4 with row offset
for ro in range(1, 4):
    exact, tf, th, lts = try_formula(
        f"H4_roff{ro}",
        lambda r, c, rv=ro: KA[((r-rv)+c)%26] if (rv<=r<=rv+25 and 0<=c<=25) else None
    )

# H1: rows=AZ, cols=KA
print("\nH1 (rows=AZ, cols=KA):")
try_formula(
    "H1_k0",
    lambda r, c: KA[(KA_IDX[AZ[r]] + c)%26] if (0<=r<=25 and 0<=c<=25) else None
)
for ro in range(1, 4):
    try_formula(
        f"H1_roff{ro}",
        lambda r, c, rv=ro: KA[(KA_IDX[AZ[r-rv]] + c)%26] if (rv<=r<=rv+25 and 0<=c<=25) else None
    )

# H4 extended: all cols wrap modularly
print("\nH4_ext (no column range restriction, just wrap):")
try_formula(
    "H4_ext",
    lambda r, c: KA[(r+c)%26] if (0<=r<=27 and 0<=c<=32) else None
)

# What if T-holes are excluded from extraction?
print("\n--- Testing with T-holes excluded from extract ---")
def try_formula_noT(name, cell_fn, holes=all_holes):
    """Test if T-excluded letters give GRILLE_EXTRACT."""
    non_t_letters = []
    t_holes = []
    for (r, c) in holes:
        v = cell_fn(r, c)
        if v is not None:
            if v == 'T':
                t_holes.append((r, c))
            else:
                non_t_letters.append(v)
    s = ''.join(non_t_letters)
    exact = (s[:106] == GE) if len(s) >= 106 else (s == GE)
    print(f"  {name}: {len(non_t_letters)} non-T letters, {len(t_holes)} T-holes, "
          f"match={exact}")
    if exact:
        print(f"    *** MATCH FOUND! T-holes: {t_holes} ***")
    return exact, t_holes, non_t_letters

# H4 with T-exclusion
try_formula_noT("H4_noT", lambda r, c: KA[(r+c)%26] if (0<=r<=27 and 0<=c<=32) else None)

# H4 with column offsets and T-exclusion
for ko in range(8):
    try_formula_noT(
        f"H4_noT_k{ko}",
        lambda r, c, k=ko: KA[(r+c-k)%26] if (0<=r<=27 and 0<=c<=32) else None
    )

# H1 with T-exclusion
try_formula_noT("H1_noT", lambda r, c: KA[(KA_IDX[AZ[r]]+c)%26] if (0<=r<=25 and 0<=c<=25) else None)

# H1 extended (cols wrap)
try_formula_noT("H1_ext_noT", lambda r, c: KA[(KA_IDX[AZ[r % 26]]+c)%26] if (0<=r<=27 and 0<=c<=32) else None)

# H4 restricted to body only (26x26), T-exclusion
try_formula_noT("H4_body_noT", lambda r, c: KA[(r+c)%26] if (0<=r<=25 and 0<=c<=25) else None)

# Also try None for out-of-body (effectively counting only in-body)
print("\n--- Body-only extraction (first 106 non-None non-T letters) ---")
for name, cell_fn in [
    ("H4_body", lambda r,c: KA[(r+c)%26] if 0<=r<=25 and 0<=c<=25 else None),
    ("H1_body", lambda r,c: KA[(KA_IDX[AZ[r]]+c)%26] if 0<=r<=25 and 0<=c<=25 else None),
    ("H4_k1", lambda r,c: KA[(r+c-1)%26] if 0<=r<=25 and 1<=c<=26 else None),
    ("H4_k2", lambda r,c: KA[(r+c-2)%26] if 0<=r<=25 and 2<=c<=27 else None),
    ("H4_k3", lambda r,c: KA[(r+c-3)%26] if 0<=r<=25 and 3<=c<=28 else None),
    ("H1_k1", lambda r,c: KA[(KA_IDX[AZ[r]]+c-1)%26] if 0<=r<=25 and 1<=c<=26 else None),
    ("H1_k2", lambda r,c: KA[(KA_IDX[AZ[r]]+c-2)%26] if 0<=r<=25 and 2<=c<=27 else None),
]:
    lts = [cell_fn(r,c) for (r,c) in all_holes if cell_fn(r,c) is not None]
    non_t = [v for v in lts if v != 'T']
    s = ''.join(non_t)
    match = (s[:106] == GE)
    print(f"  {name}: {len(lts)} letters ({len(lts)-len(non_t)} T), noT={len(non_t)}, match={match}")
    if match:
        print(f"    *** MATCH! ***")
        # Find T-holes
        t_hs = [(r,c) for (r,c) in all_holes if cell_fn(r,c)=='T']
        print(f"    T-holes: {t_hs}")

# ============================================================
# SECTION 2: T-holes under the most promising formulas
# ============================================================
print("\n=== SECTION 2: T-hole analysis ===")

# Regardless of which formula matches, let's analyze T-hole positions
# under both H4 (most common in prior work) and H1 (AZ-row theory)

def find_t_holes(cell_fn, holes=all_holes):
    return [(r,c,i) for i,(r,c) in enumerate(holes) if cell_fn(r,c)=='T']

print("\nH4 T-holes (cell=KA[(r+c)%26]):")
h4_fn = lambda r,c: KA[(r+c)%26]
t_holes_h4_raw = [(r,c,i) for i,(r,c) in enumerate(all_holes) if h4_fn(r,c)=='T']
print(f"  All T-holes (row,col,idx): {t_holes_h4_raw}")
t_idx_h4 = [i for (r,c,i) in t_holes_h4_raw]
print(f"  T-hole indices: {t_idx_h4}")

print("\nH1 T-holes (cell=KA[(KA_IDX[AZ[r]]+c)%26]):")
h1_fn = lambda r,c: KA[(KA_IDX[AZ[r]]+c)%26] if 0<=r<=25 else None
t_holes_h1_raw = [(r,c,i) for i,(r,c) in enumerate(all_holes) if h1_fn(r,c)=='T']
print(f"  All T-holes (row,col,idx): {t_holes_h1_raw}")
t_idx_h1 = [i for (r,c,i) in t_holes_h1_raw]
print(f"  T-hole indices: {t_idx_h1}")

# Segment analysis for H4 T-holes
print("\n--- Segment analysis under H4 ---")
t_in_97_h4 = [i for i in t_idx_h4 if i < 97]
print(f"T-holes within first 97: {sorted(t_in_97_h4)}")
if t_in_97_h4:
    boundaries = sorted([0] + t_in_97_h4 + [97])
    segs = []
    for k in range(len(boundaries)-1):
        segs.append((boundaries[k], boundaries[k+1]))
    print(f"Segments (K4 positions): {segs}")
    seg_lens = [e-s for s,e in segs]
    print(f"Segment lengths: {seg_lens}, sum={sum(seg_lens)}")
    # Show K4 characters in each segment
    for i, (s,e) in enumerate(segs):
        print(f"  Seg {i}: K4[{s}:{e}] = {K4_CARVED[s:e]}")

print("\n--- Segment analysis under H1 ---")
t_in_97_h1 = [i for i in t_idx_h1 if i < 97]
print(f"T-holes within first 97: {sorted(t_in_97_h1)}")
if t_in_97_h1:
    boundaries = sorted([0] + t_in_97_h1 + [97])
    segs = []
    for k in range(len(boundaries)-1):
        segs.append((boundaries[k], boundaries[k+1]))
    print(f"Segments: {segs}")
    seg_lens = [e-s for s,e in segs]
    print(f"Segment lengths: {seg_lens}, sum={sum(seg_lens)}")

# ============================================================
# SECTION 3: Segment permutation tests (new T-hole indices)
# ============================================================
print("\n=== SECTION 3: Segment permutation tests ===")

RESULTS = []
crib_hits = []

def test_candidate(label, sigma=None, candidate_ct=None):
    """Test a sigma permutation or candidate CT string."""
    global RESULTS, crib_hits
    if sigma is not None:
        if len(sigma) != N or len(set(sigma)) != N or not all(0 <= x < N for x in sigma):
            return None
        result = test_perm(sigma)
    elif candidate_ct is not None:
        if len(candidate_ct) != N:
            return None
        result = test_unscramble(candidate_ct)
    else:
        return None

    if result is None:
        return None

    score = result.get('score_per_char', -99)
    crib_hit = result.get('crib_hit', False)

    if crib_hit:
        print(f"\n{'='*60}")
        print(f"*** CRIB HIT: {label} ***")
        print(f"PT: {result.get('pt', '')}")
        print(f"Score/char: {score:.3f}")
        print(f"Key={result.get('key','')}, Cipher={result.get('cipher','')}, Alpha={result.get('alpha','')}")
        print(f"{'='*60}\n")
        crib_hits.append({'label': label, 'result': result})

    if score > -5.5:
        print(f"  [NOTABLE] {label}: {score:.3f}/char key={result.get('key','?')} {result.get('cipher','?')}/{result.get('alpha','?')}")
        RESULTS.append({'label': label, 'score': score, 'result': result})

    return result

# Test all permutations of segments for both H4 and H1 T-hole indices
def test_segment_permutations(t_indices, label_prefix, max_segs=6):
    """Test all permutations of segments defined by T-hole boundaries."""
    t_in_97 = sorted([i for i in t_indices if i < 97])
    if not t_in_97:
        print(f"  No T-holes in first 97 for {label_prefix}")
        return

    boundaries = [0] + t_in_97 + [97]
    segs = [(boundaries[k], boundaries[k+1]) for k in range(len(boundaries)-1)]
    print(f"  {len(segs)} segments: {[f'[{s}:{e}]({e-s})' for s,e in segs]}")

    if len(segs) > max_segs:
        print(f"  Too many segments ({len(segs)}), skipping exhaustive search")
        return

    n_tested = 0
    for perm in itertools.permutations(range(len(segs))):
        # Build sigma: new reading order of segments
        new_order = []
        for p in perm:
            s, e = segs[p]
            new_order.extend(range(s, e))
        assert len(new_order) == 97

        # Also try reversed segments
        for rev_bits in range(1 << len(segs)):
            sigma = []
            for bit_idx, p in enumerate(perm):
                s, e = segs[p]
                seg_positions = list(range(s, e))
                if (rev_bits >> bit_idx) & 1:
                    seg_positions = seg_positions[::-1]
                sigma.extend(seg_positions)

            test_candidate(f"{label_prefix}_perm{''.join(map(str,perm))}_rev{rev_bits:0{len(segs)}b}", sigma=sigma)
            n_tested += 1

    print(f"  Tested {n_tested} segment permutations")

print("\nH4 segment permutations:")
test_segment_permutations(t_idx_h4, "H4seg")

print("\nH1 segment permutations:")
test_segment_permutations(t_idx_h1, "H1seg")

# ============================================================
# SECTION 4: Novel approach — T-col sequence as period-26 key
# ============================================================
print("\n=== SECTION 4: T-col sequence as substitution key ===")

# T-column for AZ[r] row under H4: t_col(r) = (4-r)%26
# T-column for AZ[r] row under H1: t_col(r) = (4 - KA_IDX[AZ[r]])%26

# Build the T-col letter sequence for both formulas
# This gives a period-26 key

# H4 T-col sequence (for rows 0-25, rows in KA order but using AZ label convention)
t_col_h4_seq = [(4 - r) % 26 for r in range(26)]  # T-col for KA row r
t_key_h4_az = ''.join(AZ[tc] for tc in t_col_h4_seq)  # as AZ letters
t_key_h4_ka = ''.join(KA[tc] for tc in t_col_h4_seq)  # as KA letters
print(f"H4 T-col AZ key: {t_key_h4_az}")
print(f"H4 T-col KA key: {t_key_h4_ka}")

# H1 T-col sequence (for rows 0-25, where row r → AZ[r])
t_col_h1_seq = [(4 - KA_IDX[AZ[r]]) % 26 for r in range(26)]
t_key_h1_az = ''.join(AZ[tc] for tc in t_col_h1_seq)
t_key_h1_ka = ''.join(KA[tc] for tc in t_col_h1_seq)
print(f"H1 T-col AZ key: {t_key_h1_az}")
print(f"H1 T-col KA key: {t_key_h1_ka}")

# Test these period-26 keys directly on K4_CARVED (under Model 1 and 2)
novel_keys = [
    ("T_h4_az", t_key_h4_az),
    ("T_h4_ka", t_key_h4_ka),
    ("T_h1_az", t_key_h1_az),
    ("T_h1_ka", t_key_h1_ka),
]

# Under Model 1 (direct): test as Vigenère/Beaufort keys on K4_CARVED
print("\nDirect decryption with T-col keys (Model 1 test):")
for key_name, key in novel_keys:
    for cipher_fn, cipher_name in [(vig_decrypt, "vig"), (beau_decrypt, "beau")]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            try:
                pt = cipher_fn(K4_CARVED, key, alpha)
                score = score_text_per_char(pt)
                cribs = has_cribs(pt)
                if cribs:
                    print(f"  *** CRIB: {key_name}/{cipher_name}/{alpha_name} cribs={cribs}")
                    print(f"      PT: {pt}")
                if score > -5.0:
                    print(f"  [NOTABLE] {key_name}/{cipher_name}/{alpha_name}: {score:.3f}/char")
            except Exception:
                pass

# Under Model 2: test T-col key as unscramble + decrypt
# If we think T-col indices define σ, we need to convert to a permutation
# T_col sequence has values 0-25. For a period-26 pattern applied to 97 positions:
# sigma(j) = T_col_val[j%26] * 4 + j//26  (for grouping 97 = 4*26 - 7 - wait: 4*26=104 > 97)
# Let's try: sigma(j) = (j + T_col_val[j%26]) % 97  — shift permutation
print("\nModel 2: T-col as shift permutation (sigma(j)=(j+T_col[j%26])%97):")
for formula_name, t_col_seq in [("H4", t_col_h4_seq), ("H1", t_col_h1_seq)]:
    sigma = [(j + t_col_seq[j % 26]) % 97 for j in range(97)]
    if len(set(sigma)) == 97:
        test_candidate(f"T_shift_{formula_name}", sigma=sigma)
    else:
        print(f"  T_shift_{formula_name}: NOT a valid permutation (duplicates)")

    # Also try modular multiply
    sigma_mult = [(j * (t_col_seq[j % 26] + 1)) % 97 for j in range(97)]
    if len(set(sigma_mult)) == 97:
        test_candidate(f"T_mult_{formula_name}", sigma=sigma_mult)

# ============================================================
# SECTION 5: T-positions in K4 carved text
# ============================================================
print("\n=== SECTION 5: K4 carved text T-positions ===")

# K4 has T at positions: find them
k4_t_positions = [j for j, ch in enumerate(K4_CARVED) if ch == 'T']
print(f"K4 T-positions (carved text): {k4_t_positions}")
print(f"Count: {len(k4_t_positions)}")

# Under Model 2: K4_CARVED[sigma(j)] = real_CT[j]
# If real_CT[j] = T, then sigma(j) must be one of k4_t_positions
# real_CT[j] = T when PT[j] = T and key combination gives T

# Under Vig/KRYPTOS/AZ: PT[j] = (CT[j] - KEY[j%7]) % 26 (in AZ)
# real_CT[j] = T when PT[j] = T(AZ=19): KEY[j%7] = (CT[j] - 19) % 26
# But we don't know sigma, so we can't compute CT[j] = K4_CARVED[sigma(j)]

# Instead: what positions in the plaintext have PT=T?
# From cribs: PT[24]=T, PT[28]=T, PT[33]=T
# These MUST map to K4 positions with specific letters (depending on key)

# Compute expected real_CT letters at positions where PT=T
# Under various key/cipher/alpha combos
print("\nExpected real_CT at PT=T positions (24,28,33) under each key:")
pt_t_positions = [24, 28, 33]  # from EASTNORTHEAST

for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for cipher, cipher_fn in [("vig", vig_encrypt), ("beau", None)]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            if cipher == "beau":
                # Beaufort: CT[j] = (KEY[j] - PT[j]) % 26
                ct_at_t = []
                for pos in pt_t_positions:
                    ki = alpha.index(kw[pos % len(kw)])
                    pi = alpha.index('T')
                    ct_at_t.append(alpha[(ki - pi) % 26])
            else:
                # Vig: CT[j] = (PT[j] + KEY[j]) % 26
                ct_at_t = []
                for pos in pt_t_positions:
                    ki = alpha.index(kw[pos % len(kw)])
                    pi = alpha.index('T')
                    ct_at_t.append(alpha[(pi + ki) % 26])

            # sigma(24), sigma(28), sigma(33) must be positions in K4 with these letters
            constraints = {}
            valid = True
            for i, pos in enumerate(pt_t_positions):
                needed_letter = ct_at_t[i]
                valid_k4_positions = [j for j, ch in enumerate(K4_CARVED) if ch == needed_letter]
                constraints[pos] = (needed_letter, valid_k4_positions)

            letters = [c[0] for c in constraints.values()]
            print(f"  {kw[:6]}/{cipher}/{alpha_name}: PT[24,28,33]=T → real_CT=", end="")
            print(f"{''.join(letters)} → σ(24,28,33) must be in {[c[1][:3] for c in constraints.values()]}")

# The K4 T-positions {35,37,50,67,68,80} correspond to real_CT positions where real_CT=T
# Under Vig/KRYPTOS/AZ, real_CT[j]=T when PT[j] matches specific letter per key position
print(f"\nK4's T-positions ({k4_t_positions}) → which plaintext letters do these give?")
print("(Under Vig/KRYPTOS/AZ for various j values where sigma_inv(K4_T_pos) = j)")
kw = "KRYPTOS"
for k4_tpos in k4_t_positions:
    # For each possible real_CT position j that maps to this K4 position:
    # real_CT[j] = T → PT[j] = AZ[(AZ.index('T') - AZ.index(kw[j%7])) % 26]
    # But j is unknown (depends on sigma)
    # Instead, list what PT would be for each possible j mod 7
    pt_options = [AZ[(AZ.index('T') - AZ.index(kw[i%len(kw)])) % 26] for i in range(7)]
    print(f"  K4[{k4_tpos}]=T: if j≡0-6 mod 7 → PT = {''.join(pt_options)}")

# ============================================================
# SECTION 6: Grid overlay — K4 in width-W grid
# ============================================================
print("\n=== SECTION 6: Grid overlay — K4 in W-wide grid ===")

# What if K4 is arranged in a W-column grid?
# The Cardan grille (28×33) placed over this grid reads characters
# Holes that land on K4 positions define the reading order (sigma)

# For width W: K4[j] is at row j//W, col j%W
# Grille hole at (r_h, c_h) reads K4 position: r_h * W + c_h (if < 97)

for W in [7, 8, 9, 10, 11, 12, 13, 14, 26, 28, 33]:
    n_rows_k4 = math.ceil(97 / W)
    # Map grille holes to K4 positions
    hole_to_k4 = []
    for (r, c) in all_holes:
        k4_pos = r * W + c
        if 0 <= k4_pos < 97:
            hole_to_k4.append((r, c, k4_pos))

    # We need exactly 97 unique K4 positions covered
    k4_positions_covered = [k4 for (_, _, k4) in hole_to_k4]
    unique_covered = set(k4_positions_covered)

    print(f"  W={W}: {len(hole_to_k4)} holes map to K4, "
          f"{len(unique_covered)} unique, all={len(unique_covered)==97}")

    if len(unique_covered) == 97:
        # Build sigma: sigma[j] = K4 position at hole j (in reading order)
        # Actually sigma maps real_CT positions to carved positions
        # hole i reads K4[k4_pos_i] = real_CT[i] → sigma(i) = k4_pos_i
        sigma = [k4 for (_, _, k4) in hole_to_k4]
        if is_valid := (len(set(sigma)) == 97 and len(sigma) == 97):
            test_candidate(f"grid_W{W}", sigma=sigma)
            # Also try reversed
            sigma_rev = sigma[::-1]
            test_candidate(f"grid_W{W}_rev", sigma=sigma_rev)

# ============================================================
# SECTION 7: T-column positions directly encode σ
# ============================================================
print("\n=== SECTION 7: T-column as direct permutation encoding ===")

# For each hole j (in reading order), T_col(row_j) is a value in 0-25
# This value tells us "position" in some modular sense
# Approach: T_col * 4 + quadrant(j) → unique value 0-96?

# Compute T-cols for each hole under H4
t_cols_per_hole = []
for i, (r, c) in enumerate(all_holes):
    tc = (4 - r) % 26  # H4 formula
    tc_h1 = (4 - KA_IDX[AZ[r % 26]]) % 26 if r < 26 else None  # H1 formula
    t_cols_per_hole.append((i, r, c, tc, tc_h1))

# Try various encoding schemes
# Scheme 1: Sort first 97 holes by T_col (H4)
def make_sigma_from_order(ordered_indices, n=97):
    """Take first n indices, check validity."""
    first_n = ordered_indices[:n]
    if len(set(first_n)) == n and len(first_n) == n:
        return first_n
    return None

# Various sort keys
sort_keys = {
    'H4_tc_asc': lambda x: (x[3], x[0]),
    'H4_tc_desc': lambda x: (-x[3], x[0]),
    'H4_tc_col_asc': lambda x: (x[3], x[2], x[0]),
    'H4_tc_col_desc': lambda x: (x[3], -x[2], x[0]),
    'H4_dist_asc': lambda x: (abs(x[2] - x[3]), x[0]),  # |col - T_col|
    'H4_dist_desc': lambda x: (-abs(x[2] - x[3]), x[0]),
    'H4_circ_dist': lambda x: (min((x[2]-x[3])%26, (x[3]-x[2])%26), x[0]),
    'H4_signed_offset': lambda x: ((x[2] - x[3]) % 26, x[0]),
    'H4_roffset': lambda x: (x[1], (x[2]-x[3])%26, x[0]),
}

for sort_name, sort_key in sort_keys.items():
    sorted_holes = sorted(t_cols_per_hole, key=sort_key)
    sorted_indices = [x[0] for x in sorted_holes]
    sigma = make_sigma_from_order(sorted_indices)
    if sigma is not None:
        test_candidate(f"sort_{sort_name}", sigma=sigma)

# ============================================================
# SECTION 8: T-hole coordinates as base-97 encoding
# ============================================================
print("\n=== SECTION 8: T-hole coordinate encoding ===")

# Get T-holes under H4
t_holes_h4 = [(r, c, i) for i, (r, c) in enumerate(all_holes) if (r+c)%26 == 4]
print(f"H4 T-holes: {t_holes_h4}")

if t_holes_h4:
    # T-hole positions: (row, col, reading_index)
    # Their reading indices divide the holes into segments
    # Try all orderings of these segments
    t_reading_indices = sorted([i for (r,c,i) in t_holes_h4 if i < 97])
    print(f"T-hole reading indices (in first 97): {t_reading_indices}")

    # The T-holes define "split points" in the reading
    # Segments between consecutive T-holes
    boundaries = [0] + t_reading_indices + [97]
    segments = [(boundaries[k], boundaries[k+1]) for k in range(len(boundaries)-1)]
    print(f"Segments: {[(s,e,e-s) for s,e in segments]}")

    # Test permutations
    n_segs = len(segments)
    if n_segs <= 7:
        n_tested = 0
        for perm in itertools.permutations(range(n_segs)):
            for rev_bits in range(1 << n_segs):
                sigma = []
                for bit_idx, seg_idx in enumerate(perm):
                    s, e = segments[seg_idx]
                    positions = list(range(s, e))
                    if (rev_bits >> bit_idx) & 1:
                        positions = positions[::-1]
                    sigma.extend(positions)
                if len(sigma) == 97:
                    test_candidate(f"H4seg_p{''.join(map(str,perm))}_r{rev_bits:0{n_segs}b}", sigma=sigma)
                    n_tested += 1
        print(f"Tested {n_tested} H4-segment permutations")

# Also test H1 T-holes
t_holes_h1_list = [(r, c, i) for i, (r, c) in enumerate(all_holes)
                   if r < 26 and (KA_IDX[AZ[r]] + c) % 26 == 4]
print(f"\nH1 T-holes: {t_holes_h1_list}")

if t_holes_h1_list:
    t_reading_h1 = sorted([i for (r,c,i) in t_holes_h1_list if i < 97])
    print(f"H1 T-hole reading indices (in first 97): {t_reading_h1}")
    boundaries_h1 = [0] + t_reading_h1 + [97]
    segments_h1 = [(boundaries_h1[k], boundaries_h1[k+1]) for k in range(len(boundaries_h1)-1)]
    n_segs_h1 = len(segments_h1)
    if n_segs_h1 <= 7 and n_segs_h1 >= 2:
        n_tested = 0
        for perm in itertools.permutations(range(n_segs_h1)):
            for rev_bits in range(1 << n_segs_h1):
                sigma = []
                for bit_idx, seg_idx in enumerate(perm):
                    s, e = segments_h1[seg_idx]
                    positions = list(range(s, e))
                    if (rev_bits >> bit_idx) & 1:
                        positions = positions[::-1]
                    sigma.extend(positions)
                if len(sigma) == 97:
                    test_candidate(f"H1seg_p{''.join(map(str,perm))}_r{rev_bits:0{n_segs_h1}b}", sigma=sigma)
                    n_tested += 1
        print(f"Tested {n_tested} H1-segment permutations")

# ============================================================
# SECTION 9: T-col in KA order (novel key application)
# ============================================================
print("\n=== SECTION 9: T-col KA-order key on K4 ===")

# T_col sequence for rows in KA ORDER (row r has key KA[r]):
# T_col_KA(r) = (4 - r) % 26 (since cell = KA[(r+c)%26] → T when c=(4-r)%26)
# The 26 T-col values for rows in KA order:
t_cols_ka_order = [(4 - r) % 26 for r in range(26)]
# As AZ letters: AZ[tc]
t_key_ka_order_az = ''.join(AZ[tc] for tc in t_cols_ka_order)
# As KA letters: KA[tc]
t_key_ka_order_ka = ''.join(KA[tc] for tc in t_cols_ka_order)

print(f"T-col key (KA-row order, AZ letters): {t_key_ka_order_az}")
print(f"T-col key (KA-row order, KA letters): {t_key_ka_order_ka}")

# Test these as period-26 Vigenère/Beaufort keys on K4 directly
print("\nDirect Vig/Beau with period-26 T-col keys:")
for key_name, key in [
    ("T_ka_az", t_key_ka_order_az),
    ("T_ka_ka", t_key_ka_order_ka),
    ("T_ka_az_rev", t_key_ka_order_az[::-1]),
    ("T_ka_ka_rev", t_key_ka_order_ka[::-1]),
]:
    for cipher_fn, cipher_name in [(vig_decrypt, "vig"), (beau_decrypt, "beau")]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            try:
                pt = cipher_fn(K4_CARVED, key, alpha)
                score = score_text_per_char(pt)
                cribs = has_cribs(pt)
                if cribs:
                    print(f"  *** CRIB! {key_name}/{cipher_name}/{alpha_name}: {cribs}")
                    print(f"    PT: {pt}")
                elif score > -5.0:
                    print(f"  [NOTABLE] {key_name}/{cipher_name}/{alpha_name}: {score:.3f}/char")
            except Exception as e:
                pass

# ============================================================
# SECTION 10: "T is your position" = T position in each row
# defines the COLUMN ordering of K4
# ============================================================
print("\n=== SECTION 10: T-col as column order for K4 ===")

# Map each real_CT position j to a "T-col value":
# The KA tableau row for position j (based on key) has T at some column.
# That T-col value encodes the permutation.

# If the key is KRYPTOS with period 7:
kw = "KRYPTOS"
# For each position j in real_CT, the key letter is kw[j%7]
# Row for that key letter (in H4 = KA order): row = KA_IDX[kw[j%7]]
# T-col for that row = (4 - KA_IDX[kw[j%7]]) % 26
# This gives a repeating pattern of 7 T-col values

kryptos_t_cols = [(4 - KA_IDX[kw[j % 7]]) % 26 for j in range(97)]
print(f"KRYPTOS T-col pattern for j=0..96: {kryptos_t_cols[:14]}... (period 7)")

# The T-col value for position j is in 0-25.
# sigma(j) could be: (j + t_col) % 97
sigma_t_kryptos_shift = [(j + kryptos_t_cols[j]) % 97 for j in range(97)]
if len(set(sigma_t_kryptos_shift)) == 97:
    test_candidate("KRYPTOS_t_shift", sigma=sigma_t_kryptos_shift)
else:
    print(f"  KRYPTOS_t_shift: not a valid permutation ({len(set(sigma_t_kryptos_shift))} unique)")

# Inverse shift
sigma_t_kryptos_neg = [(j - kryptos_t_cols[j]) % 97 for j in range(97)]
if len(set(sigma_t_kryptos_neg)) == 97:
    test_candidate("KRYPTOS_t_neg_shift", sigma=sigma_t_kryptos_neg)

# For all keywords
for kw in KEYWORDS:
    kw_t_cols = [(4 - KA_IDX[kw[j % len(kw)]]) % 26 for j in range(97)]
    for name_suffix, sigma_fn in [
        ("shift", lambda j, k=kw_t_cols: (j + k[j]) % 97),
        ("neg", lambda j, k=kw_t_cols: (j - k[j]) % 97),
        ("mult", lambda j, k=kw_t_cols: (j * (k[j]+1)) % 97),
    ]:
        sigma = [sigma_fn(j) for j in range(97)]
        if len(set(sigma)) == 97:
            test_candidate(f"{kw}_{name_suffix}", sigma=sigma)

# ============================================================
# SECTION 11: Grille extract as position map
# ============================================================
print("\n=== SECTION 11: Grille extract as σ guide ===")

# The 106 chars of GE are letters. Their positions in AZ/KA give values.
# If we use first 97: GE[j] → AZ_idx or KA_idx → sigma value?

ge_az = [AZ_IDX[c] for c in GE[:97]]  # 0-25 range
ge_ka = [KA_IDX[c] for c in GE[:97]]  # 0-25 range

# sigma(j) = GE_AZ[j] * 4 + j//26 → might not be valid perm
# Alternative: rank-order GE[0..96] to get permutation
from functools import cmp_to_key

# Rank order: sigma(j) = rank of GE[j] in sorted order (stable, AZ key)
sorted_j_az = sorted(range(97), key=lambda j: (ge_az[j], j))
sigma_ge_rank_az = [0]*97
for rank, j in enumerate(sorted_j_az):
    sigma_ge_rank_az[j] = rank
test_candidate("GE_rank_az", sigma=sigma_ge_rank_az)

sorted_j_ka = sorted(range(97), key=lambda j: (ge_ka[j], j))
sigma_ge_rank_ka = [0]*97
for rank, j in enumerate(sorted_j_ka):
    sigma_ge_rank_ka[j] = rank
test_candidate("GE_rank_ka", sigma=sigma_ge_rank_ka)

# Inverse: sigma(rank) = j
test_candidate("GE_inv_rank_az", sigma=sorted_j_az)
test_candidate("GE_inv_rank_ka", sigma=sorted_j_ka)

# ============================================================
# SECTION 12: Period-8 connection to T-col
# ============================================================
print("\n=== SECTION 12: Period-8 + T-col hybrid ===")

# The period-8 observation: rows F(5), N(13), V(21) are special
# These are code rows 5, 13, 21 (0-indexed)
# Under H4: T at (5, (4-5)%26)=(5,25), (13,(4-13)%26)=(13,17), (21,(4-21)%26)=(21,9)
# Under H1: T at rows F,N,V:
# F=AZ[5], KA_IDX[F]=12: T_col=(4-12)%26=18 → (5,18)
# N=AZ[13], KA_IDX[N]=19: T_col=(4-19)%26=11 → (13,11)
# V=AZ[21], KA_IDX[V]=22: T_col=(4-22)%26=8 → (21,8)

period8_special_rows = [5, 13, 21]
print(f"Period-8 special rows: {period8_special_rows}")

for formula_name, t_col_fn in [
    ("H4", lambda r: (4-r)%26),
    ("H1", lambda r: (4-KA_IDX[AZ[r]])%26 if r<26 else None),
]:
    sp_t_cols = [t_col_fn(r) for r in period8_special_rows]
    print(f"  {formula_name}: T-cols at period-8 rows: {sp_t_cols}")

    # Check if these T-positions coincide with holes
    for r, tc in zip(period8_special_rows, sp_t_cols):
        if tc is None:
            continue
        holes_in_row = [c for (rr, c) in all_holes if rr == r]
        at_t = tc in holes_in_row
        print(f"    Row {r}: T at col {tc}, holes at {holes_in_row}, T-hole? {at_t}")

# K4 arranged in 8 columns → T-diagonal alignment
print("\nK4 in 8-column grid, T-diagonal positions:")
W = 8
for pos in range(97):
    r, c = pos // W, pos % W
    # Under H4: T at (r, (4-r)%26)%8 in the K4 grid
    # The T-diagonal in the 8-col grid passes through col (4-r)%8 for each row
    t_col_in_grid = (4 - r) % 8
    if c == t_col_in_grid:
        print(f"  K4 pos {pos} (row {r}, col {c}): K4={K4_CARVED[pos]} is on T-diagonal mod8")

# ============================================================
# SECTION 13: Simulated annealing with T-position seeds
# ============================================================
print("\n=== SECTION 13: T-seeded simulated annealing ===")

import random

def compute_expected_ct(keyword, cipher_type, alpha=AZ):
    """Compute expected real_CT at crib positions."""
    expected = {}
    for crib_pos, crib_text in [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]:
        for j, pt_char in enumerate(crib_text):
            pos = crib_pos + j
            ki = alpha.index(keyword[pos % len(keyword)])
            pi = alpha.index(pt_char)
            if cipher_type == "vig":
                expected[pos] = alpha[(pi + ki) % 26]
            else:  # beau
                expected[pos] = alpha[(ki - pi) % 26]
    return expected

def sa_with_crib_pins(keyword, cipher_type, alpha, n_iters=50000, seed=42):
    """SA: pin 24 crib positions, optimize 73 free positions."""
    random.seed(seed)

    # Expected real_CT at crib positions
    expected = compute_expected_ct(keyword, cipher_type, alpha)

    # Find valid sigma values for each crib position
    crib_sigma = {}
    valid = True
    for pos, expected_letter in expected.items():
        valid_positions = [j for j, ch in enumerate(K4_CARVED) if ch == expected_letter]
        if not valid_positions:
            valid = False
            break
        crib_sigma[pos] = valid_positions

    if not valid:
        return None

    # Build initial sigma with cribs pinned
    sigma = list(range(97))  # identity to start
    used = set()

    # Pin crib positions
    pinned = {}
    for pos in sorted(expected.keys()):
        options = [p for p in crib_sigma[pos] if p not in used]
        if not options:
            return None  # Can't pin
        chosen = options[0]  # Take first available
        sigma[pos] = chosen
        used.add(chosen)
        pinned[pos] = chosen

    # Fill free positions
    free_positions = [j for j in range(97) if j not in pinned]
    free_k4_positions = [j for j in range(97) if j not in used]
    random.shuffle(free_k4_positions)
    for i, pos in enumerate(free_positions):
        sigma[pos] = free_k4_positions[i]

    # Score function
    def score_sigma(s):
        ct = ''.join(K4_CARVED[s[j]] for j in range(97))
        if cipher_type == "vig":
            pt = vig_decrypt(ct, keyword, alpha)
        else:
            pt = beau_decrypt(ct, keyword, alpha)
        return score_text(pt)

    current_score = score_sigma(sigma)
    best_sigma = sigma[:]
    best_score = current_score

    T_sa = 5.0  # SA temperature
    for it in range(n_iters):
        # Swap two free positions
        if len(free_positions) < 2:
            break
        i1, i2 = random.sample(range(len(free_positions)), 2)
        p1, p2 = free_positions[i1], free_positions[i2]
        sigma[p1], sigma[p2] = sigma[p2], sigma[p1]

        new_score = score_sigma(sigma)
        delta = new_score - current_score

        if delta > 0 or random.random() < math.exp(delta / T_sa):
            current_score = new_score
            if current_score > best_score:
                best_score = current_score
                best_sigma = sigma[:]
        else:
            sigma[p1], sigma[p2] = sigma[p2], sigma[p1]

        T_sa *= 0.9999

    return best_sigma, best_score

# Run SA for most promising configs
print("\nRunning SA with crib pins (short run, 50K iters each):")
best_sa_results = []
for kw in ["KRYPTOS", "PALIMPSEST"]:
    for cipher in ["vig", "beau"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            try:
                result = sa_with_crib_pins(kw, cipher, alpha, n_iters=50000)
                if result is not None:
                    sigma, sa_score = result
                    # Check cribs
                    ct = ''.join(K4_CARVED[sigma[j]] for j in range(97))
                    if cipher == "vig":
                        pt = vig_decrypt(ct, kw, alpha)
                    else:
                        pt = beau_decrypt(ct, kw, alpha)

                    has_ene = "EASTNORTHEAST" in pt
                    has_bc = "BERLINCLOCK" in pt

                    if has_ene or has_bc:
                        print(f"  *** CRIB! SA {kw}/{cipher}/{alpha_name}: ENE={has_ene} BC={has_bc}")
                        print(f"      PT: {pt}")
                        print(f"      Score: {sa_score:.2f}")

                    score_pc = sa_score / 94
                    if score_pc > -5.5:
                        print(f"  [NOTABLE] SA {kw}/{cipher}/{alpha_name}: {score_pc:.3f}/char")

                    best_sa_results.append({
                        'key': kw, 'cipher': cipher, 'alpha': alpha_name,
                        'score': sa_score, 'score_pc': score_pc
                    })
            except Exception as e:
                print(f"  SA {kw}/{cipher}/{alpha_name} error: {e}")

if best_sa_results:
    best_sa_results.sort(key=lambda x: -x['score'])
    print(f"\nBest SA results:")
    for r in best_sa_results[:5]:
        print(f"  {r['key']}/{r['cipher']}/{r['alpha']}: {r['score_pc']:.3f}/char")

# ============================================================
# FINAL SUMMARY
# ============================================================
print("\n" + "="*60)
print("FINAL SUMMARY")
print("="*60)

print(f"\nTotal crib hits: {len(crib_hits)}")
for hit in crib_hits:
    print(f"  {hit['label']}: {hit['result'].get('pt','')[:60]}")

print(f"\nNotable results (score > -5.5/char): {len(RESULTS)}")
for r in sorted(RESULTS, key=lambda x: -x['score'])[:10]:
    print(f"  {r['label']}: {r['score']:.3f}/char")

# Save results
output = {
    'crib_hits': [{'label': h['label'], 'pt': h['result'].get('pt', '')} for h in crib_hits],
    'notable': [{'label': r['label'], 'score': r['score']} for r in RESULTS],
    'mask_holes_count': len(all_holes),
    'h4_t_holes': t_holes_h4_raw,
    'h1_t_holes': t_holes_h1_raw,
}
with open('results/blitz_t_v2/summary.json', 'w') as f:
    json.dump(output, f, indent=2)
print("\nResults saved to results/blitz_t_v2/summary.json")

if not crib_hits:
    print("\n[VERDICT] No crib hits found. T-position avenue remains exhausted.")
    print("Correct mask (1=HOLE) gives different T-hole positions than prior scripts.")
    print("But neither formula gives a breakthrough permutation.")
