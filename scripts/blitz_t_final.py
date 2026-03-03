#!/usr/bin/env python3
"""
blitz_t_final.py — Final T-position approaches with CORRECT alphabet-bounds check.

KEY INSIGHT: Hole (6,0) is OUTSIDE the alphabet for k=2 (alphabet starts at col 2).
The condition for T requires BOTH:
  1. c is IN alphabet range [k, k+25]
  2. (c-k+r)%26 == 4

This explains why k=2 gives 0 T-letters from valid holes.
The "107 holes, 106 with letters" = hole (6,0) is the no-letter hole (outside alphabet).

New approaches:
  1. Correctly compute k=2 letters for all 106 valid holes
  2. T-position approaches using k=2-corrected values
  3. Reverse composition: vig_dec THEN permute (vs. usual permute THEN vig_dec)
  4. More segment/grouping approaches based on T-positions [12,21,33,90]
  5. Keyed columnar with actual English keywords
  6. T-hole K4 chars as key extractors
"""

import sys, json, os, math, itertools
from collections import defaultdict, Counter

sys.path.insert(0, 'src')

K4  = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA  = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
CRIB1 = "EASTNORTHEAST"
CRIB2 = "BERLINCLOCK"

# Extended keywords including less common ones
KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
            'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA',
            'LAYER','ILLUSION','IQLUSION','COMPASS','PYRAMID','AGENCY','JAMES',
            'JAMES','WILLIAM','FOUR','THREE','CLUE','DECODE','SECRET','HIDDEN',
            'SCULPTURE','STATUE','LANGLEY','VIRGINIA','CENTRAL','INTELLIGENCE',
            'KRYPTOS','KRYPTOSAB','BFSA','NORTHEAST','NORTHEAST']

# Deduplicate
KEYWORDS = list(dict.fromkeys(KEYWORDS))

OUT_DIR = 'blitz_results/t_position'
os.makedirs(OUT_DIR, exist_ok=True)

qg = json.load(open('data/english_quadgrams.json'))
def qgscore(text):
    return sum(qg.get(text[i:i+4].upper(), -10.0) for i in range(len(text)-3))

SCORE_THRESHOLD = -600

MASK_TEXT = """1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    ~
0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    1    1    0    1    1    1    1    0    0    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    1    0    ~    ~
1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    0    0    1    0    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    0    ~
1    1    1    1    0    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    ~    ~
1    1    0    1    1    0    1    1    1    1    0    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    0    1    ~    ~
1    1    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    0    1    1    0    1    1    0    ~    ~
1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    0    1    1    0    1    1    0    1    1    ~
1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    0    1    1
0    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    0    ~    ~
1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    ~    ~"""

HOLES = []
for r, line in enumerate(MASK_TEXT.strip().split('\n')):
    vals = line.split()
    for c, v in enumerate(vals):
        if v == '0':
            HOLES.append((r, c))

assert len(HOLES) == 107

# ── CORRECTED offset analysis ─────────────────────────────────────────────────
print("═══ CORRECTED Alphabet-Bounds Column Offset Analysis ═══")
print("T at (r,c) iff k<=c<=k+25 AND (c-k+r)%26==4")
print()

valid_k_offsets = []
for k in range(33):
    # Check only holes where alphabet covers: k <= c <= k+25
    in_alphabet = [(i, r, c) for i,(r,c) in enumerate(HOLES) if k <= c <= k+25]
    t_hits = [(i, r, c) for i,r,c in in_alphabet if (c-k+r)%26 == 4]
    outside = [(i,r,c) for i,(r,c) in enumerate(HOLES) if not (k <= c <= k+25)]

    if len(t_hits) == 0:
        valid_k_offsets.append(k)
        print(f"  k={k:2d}: T-hits=0, in-alphabet={len(in_alphabet)}, outside={len(outside)}")
        if len(in_alphabet) == 106:
            print(f"    *** PERFECT: exactly 106 in-alphabet holes (1 outside = no-letter hole)")

print(f"\nValid offsets (0 T-hits in alphabet): {valid_k_offsets}")

# ── For each valid k, extract corrected letters ───────────────────────────────
def get_corrected_extract(k_offset):
    """Get 106 letters from valid alphabet holes with offset k."""
    letters = []
    valid_holes = []
    for i, (r, c) in enumerate(HOLES):
        if k_offset <= c <= k_offset + 25:
            letter = KA[(c - k_offset + r) % 26]
            letters.append(letter)
            valid_holes.append(i)
    return letters, valid_holes

# ── Utilities ─────────────────────────────────────────────────────────────────
def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)

def invert_perm(perm):
    inv = [0]*len(perm)
    for i,p in enumerate(perm): inv[p] = i
    return inv

def is_valid_perm(perm, n=97):
    return len(perm) == n and set(perm) == set(range(n))

def vig_dec(ct, key, alpha=AZ):
    out = []
    for i,c in enumerate(ct):
        ci = alpha.find(c); ki = alpha.find(key[i % len(key)])
        if ci < 0 or ki < 0: return None
        out.append(alpha[(ci - ki) % 26])
    return ''.join(out)

def beau_dec(ct, key, alpha=AZ):
    out = []
    for i,c in enumerate(ct):
        ci = alpha.find(c); ki = alpha.find(key[i % len(key)])
        if ci < 0 or ki < 0: return None
        out.append(alpha[(ki - ci) % 26])
    return ''.join(out)

def stable_rank(vals):
    return sorted(range(len(vals)), key=lambda i: (vals[i], i))

RESULTS = []
tested_perms = set()
tested_direct = set()

def test_perm(perm, name="unnamed", verbose=False):
    """Test permutation: apply_perm(K4, perm) → vig_dec → search for cribs."""
    if not is_valid_perm(perm): return None
    key = tuple(perm)
    if key in tested_perms: return None
    tested_perms.add(key)

    candidate_ct = apply_perm(K4, perm)
    best = None
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(candidate_ct, kw, alpha)
                if pt is None: continue
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n{'='*70}")
                    print(f"*** CRIB HIT [{name}]: ENE@{ene} BC@{bc}")
                    print(f"    key={kw} cipher={cipher_name}/{alpha_name}")
                    print(f"    CT: {candidate_ct}")
                    print(f"    PT: {pt}")
                    print(f"    Score: {sc:.2f}")
                    print(f"{'='*70}\n")
                    RESULTS.append({'type':'perm','name':name,'score':sc,'perm':list(perm),'pt':pt,'key':kw,'cipher':cipher_name,'alpha':alpha_name,'ct':candidate_ct})
                if best is None or sc > best[0]:
                    best = (sc, name, pt, kw, cipher_name, alpha_name, candidate_ct)
    if best and best[0] > SCORE_THRESHOLD:
        RESULTS.append({'type':'perm','name':name,'score':best[0],'perm':list(perm),'pt':best[2],'key':best[3],'cipher':best[4],'alpha':best[5],'ct':best[6]})
        if verbose:
            print(f"  {name}: {best[0]:.2f} [{best[3]}/{best[4]}/{best[5]}]")
    return best

def test_direct(ct_or_key_pair, name="unnamed"):
    """Test: vig_dec(K4, key) = PT directly (no permutation)."""
    pass  # handled inline

def test_reverse_composition(perm, name="unnamed"):
    """Test REVERSE order: vig_dec(K4, kw) → apply_perm(result, perm)."""
    if not is_valid_perm(perm): return None
    best = None
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                intermediate = fn(K4, kw, alpha)
                if intermediate is None: continue
                pt = apply_perm(intermediate, perm)
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n{'='*70}")
                    print(f"*** CRIB HIT [REVERSE/{name}]: ENE@{ene} BC@{bc}")
                    print(f"    key={kw} cipher={cipher_name}/{alpha_name}")
                    print(f"    intermediate: {intermediate}")
                    print(f"    PT: {pt}")
                    print(f"    Score: {sc:.2f}")
                    print(f"{'='*70}\n")
                    RESULTS.append({'type':'reverse','name':f'REV_{name}','score':sc,'perm':list(perm),'pt':pt,'key':kw,'cipher':cipher_name,'alpha':alpha_name})
                if best is None or sc > best[0]:
                    best = (sc, pt, kw, cipher_name, alpha_name)
    if best and best[0] > SCORE_THRESHOLD:
        RESULTS.append({'type':'reverse','name':f'REV_{name}','score':best[0],'perm':list(perm),'pt':best[1],'key':best[2],'cipher':best[3],'alpha':best[4]})
    return best

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: Test each valid k with corrected letters
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 1: Corrected-k tableau key approaches ═══")

for k in valid_k_offsets:
    letters, valid_hole_indices = get_corrected_extract(k)
    t_count_k = letters.count('T')
    print(f"\n  k={k}: {len(letters)} letters, T-count={t_count_k}")
    if t_count_k > 0:
        print(f"    SKIP: T appears {t_count_k} times")
        continue

    print(f"  Extract[k={k}]: {''.join(letters[:30])}...")
    print(f"  vs GRILLE_EXTRACT:          {GRILLE_EXTRACT[:30]}...")

    # Note: valid_hole_indices are HOLE LIST indices (not K4 positions directly)
    # valid_hole_indices[j] = index into HOLES[] list of j-th valid (in-alphabet) hole
    # The j-th letter corresponds to HOLES[valid_hole_indices[j]]

    # The first 97 valid holes map to K4 positions 0..96
    # (assuming the 107 holes are in reading order and k4 position = hole reading order)
    valid97 = valid_hole_indices[:97]  # first 97 valid holes

    # Method 1: Tableau key → Vig/Beau decrypt of K4
    key97 = ''.join(letters[:97])
    for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            pt = fn(K4, key97, alpha)
            if pt:
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT [k{k}_tableau_key/{cipher_name}/{alpha_name}]: ENE@{ene} BC@{bc}")
                    print(f"    PT: {pt}")
                if sc > SCORE_THRESHOLD:
                    print(f"  k{k}_tableau_key_{cipher_name}_{alpha_name}: score={sc:.2f}")

    # Method 2: Sort K4 positions by corrected letter rank
    letter_ranks = [KA.index(letters[j]) for j in range(97)]
    perm_by_rank = stable_rank(letter_ranks)
    if is_valid_perm(perm_by_rank):
        test_perm(perm_by_rank, f'k{k}_corrected_rank', verbose=True)
        test_perm(invert_perm(perm_by_rank), f'k{k}_corrected_rank_inv', verbose=True)
        test_reverse_composition(perm_by_rank, f'k{k}_corrected_rank')

    # Method 3: T-relative offset with corrected formula
    t_offs_k = [(c - k - (4 - r) % 26) % 26 for (r,c) in [HOLES[vi] for vi in valid97]]
    perm_toff_k = stable_rank(t_offs_k)
    if is_valid_perm(perm_toff_k):
        test_perm(perm_toff_k, f'k{k}_corrected_toffset_rank', verbose=True)

    # Method 4: T-distance with corrected formula
    t_dists_k = [abs(c - k - (4-r)%26) for (r,c) in [HOLES[vi] for vi in valid97]]
    perm_tdist_k = stable_rank(t_dists_k)
    if is_valid_perm(perm_tdist_k):
        test_perm(perm_tdist_k, f'k{k}_corrected_tdist_rank', verbose=True)

    # Method 5: Corrected letter as columnar key
    for W in [7, 8, 13, 14, 26, 28]:
        col_key = letter_ranks[:W]
        col_order = sorted(range(W), key=lambda c: (col_key[c], c))
        n_rows_g = math.ceil(97/W)
        perm_col = []
        for c in col_order:
            for r_idx in range(n_rows_g):
                idx = r_idx * W + c
                if idx < 97: perm_col.append(idx)
        if is_valid_perm(perm_col):
            test_perm(perm_col, f'k{k}_corrected_col_W{W}', verbose=True)
            test_perm(invert_perm(perm_col), f'k{k}_corrected_col_inv_W{W}', verbose=True)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: Reverse composition with all previously-tested permutations
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 2: Reverse composition (vig_dec THEN permute) ═══")
print("Testing: vig_dec(K4, kw) → permute result → search for cribs")

# Key grille-derived permutations to test in reverse order
def make_columnar_perm(key_vals, W, n=97):
    """Standard columnar transposition permutation."""
    col_order = sorted(range(W), key=lambda c: (key_vals[c % len(key_vals)], c))
    n_rows = math.ceil(n / W)
    perm = []
    for c in col_order:
        for r_idx in range(n_rows):
            idx = r_idx * W + c
            if idx < n: perm.append(idx)
    return perm if is_valid_perm(perm, n) else None

# T-offsets and distances (with k=0 formula: (c+r)%26=4 are T-holes)
t_offs_k0 = [(c - (4-r)%26 + 100*26) % 26 for (r,c) in HOLES[:97]]
t_dists_k0 = [abs(c - (4-r)%26) for (r,c) in HOLES[:97]]

for name, vals in [
    ("toff_k0", t_offs_k0),
    ("tdist_k0", t_dists_k0),
    ("extract_ka", [KA.index(c) for c in GRILLE_EXTRACT[:97]]),
    ("hole_row", [r for (r,c) in HOLES[:97]]),
    ("hole_col", [c for (r,c) in HOLES[:97]]),
]:
    perm = stable_rank(vals)
    if is_valid_perm(perm):
        test_reverse_composition(perm, name)
        test_reverse_composition(invert_perm(perm), f'{name}_inv')

    for W in [7, 8, 13, 26, 28]:
        p = make_columnar_perm(vals, W)
        if p:
            test_reverse_composition(p, f'{name}_col_W{W}')
            test_reverse_composition(invert_perm(p), f'{name}_col_inv_W{W}')

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: T-hole K4 chars as keywords
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 3: T-hole K4 chars as keywords ═══")

# T-holes in first 97 holes: [12, 21, 33, 90]
t4_indices = [12, 21, 33, 90]
t4_k4_chars = [K4[i] for i in t4_indices]
print(f"K4 chars at T-hole positions {t4_indices}: {''.join(t4_k4_chars)}")

# Also check the 5th T-hole (105 > 97, so out of K4 range)
# But in the 107-hole grille: hole[105] = (27,29). Not a K4 position.

# What are the GRILLE_EXTRACT chars corresponding to T-holes?
# The T-holes at indices 12,21,33,90 in the reading order:
# But GRILLE_EXTRACT doesn't include T-holes (they ARE T → excluded from extract)
# So GRILLE_EXTRACT[0..105] with T's reinserted: indices [12,21,33,90,105] are T

# Extract chars just BEFORE and AFTER each T-hole
for t_idx in t4_indices:
    before = [GRILLE_EXTRACT[t_idx-1] if t_idx > 0 else None]  # before T, adjusted for prior T's
    # This is complex due to T's being excluded from GRILLE_EXTRACT
    # Just use GRILLE_EXTRACT index directly (T's excluded, so indices shift)
    ge_idx = t_idx - sum(1 for ti in t4_indices if ti < t_idx)  # adjust for excluded T's
    if 0 <= ge_idx < 106:
        print(f"  T-hole {t_idx}: GRILLE_EXTRACT[{ge_idx}]={GRILLE_EXTRACT[ge_idx]}")

# Try various combinations as keywords
extra_keywords = []
for combo_len in range(4, 9):
    for start in range(len(t4_indices)):
        if start + combo_len <= 97:
            chars_from_k4 = K4[start:start+combo_len]
            extra_keywords.append(chars_from_k4)

# Also: chars BETWEEN T-holes
segs = [[K4[i] for i in range(0,12)],  # before T-hole 12
        [K4[i] for i in range(12,21)], # between 12 and 21
        [K4[i] for i in range(21,33)], # between 21 and 33
        [K4[i] for i in range(33,90)], # between 33 and 90
        [K4[i] for i in range(90,97)]] # after T-hole 90

print(f"\nK4 segments between T-holes:")
for i, seg in enumerate(segs):
    print(f"  Seg {i}: {''.join(seg)}")

# Try each segment as a keyword (take first/last 4-8 chars)
for seg in segs:
    for klen in [4, 5, 6, 7, 8]:
        if len(seg) >= klen:
            kw = ''.join(seg[:klen])
            for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    pt = fn(K4, kw, alpha)
                    if pt:
                        sc = qgscore(pt)
                        ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                        if ene >= 0 or bc >= 0:
                            print(f"\n*** CRIB HIT [seg_key/{kw}/{cipher_name}/{alpha_name}]: ENE@{ene} BC@{bc}")
                            print(f"    PT: {pt}")
                        if sc > SCORE_THRESHOLD:
                            print(f"  seg_key_{kw}_{cipher_name}_{alpha_name}: score={sc:.2f}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: Keyed columnar with actual English keywords
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 4: Keyed columnar with actual English keywords ═══")

def keyword_columnar_perm(keyword, n=97):
    """Standard keyed columnar transposition using keyword for column ordering."""
    W = len(keyword)
    if W == 0 or W > n: return None
    # Assign ranks to keyword letters (stable sort)
    ranks = sorted(range(W), key=lambda i: (AZ.find(keyword[i]), i))
    col_order = [0] * W
    for rank, col_idx in enumerate(ranks):
        col_order[rank] = col_idx
    # Wait, col_order should be: col_order[rank] = which column to read at rank-th position
    # More precisely: read columns in order of their rank in the keyword
    # col_order = argsort(keyword_ranks)
    col_order = sorted(range(W), key=lambda c: (AZ.find(keyword[c]) if keyword[c] in AZ else 99, c))
    n_rows = math.ceil(n / W)
    perm = []
    for c in col_order:
        for r_idx in range(n_rows):
            idx = r_idx * W + c
            if idx < n: perm.append(idx)
    return perm if is_valid_perm(perm, n) else None

kw_for_columnar = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
    'BERLIN', 'BERLINCLOCK', 'CLOCK', 'NORTHEAST', 'EAST', 'NORTH',
    'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA', 'LAYER', 'ILLUSION',
    'COMPASS', 'PYRAMID', 'LANGLEY', 'VIRGINIA',
    # Also try known K4-related strings
    'EASTNORTHEAST', 'NYPVTTMZFPK', 'OBKRU',
]

count_kw = 0
for kw in kw_for_columnar:
    p = keyword_columnar_perm(kw)
    if p:
        test_perm(p, f'keyed_col_{kw}')
        test_perm(invert_perm(p), f'keyed_col_inv_{kw}')
        test_reverse_composition(p, f'keyed_col_{kw}')
        count_kw += 1

print(f"  Tested {count_kw} keyword-based columnar permutations")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: Direct arithmetic permutations based on T-structure
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 5: Direct arithmetic permutations ═══")

# T-hole positions: 12, 21, 33, 90 → these modulo various numbers
for modular in [97, 26, 25, 28]:
    t_mod = [ti % modular for ti in t4_indices]
    print(f"  T-positions mod {modular}: {t_mod}")

# Rotation by T-based values
T_AZ_idx = 19  # T in AZ (0-indexed)
T_KA_idx = 4   # T in KA (0-indexed)

for shift in [12, 21, 33, 90, 9, 57, 7, 12+21, 21+33, 33+90,
              T_AZ_idx, T_KA_idx, 97-T_AZ_idx, 97-T_KA_idx,
              12*2, 21*2%97, 33*2%97, 90*2%97]:
    perm = [(i + shift) % 97 for i in range(97)]
    if is_valid_perm(perm):
        test_perm(perm, f'rotation_{shift}', verbose=False)

# XOR-based
for xor_val in [12, 21, 33, 90, T_AZ_idx, T_KA_idx]:
    perm = [i ^ xor_val for i in range(97)]
    # XOR may not give valid perm; use rank
    perm_rank = stable_rank([i ^ xor_val for i in range(97)])
    if is_valid_perm(perm_rank):
        test_perm(perm_rank, f'xor_rank_{xor_val}', verbose=False)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6: The "8 Lines 73" hint from KryptosFan
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 6: '8 Lines 73' yellow pad hint ═══")
# "8 Lines 73" suggests K4 is laid in 8 lines of ~12 chars each
# 8 lines × 12 cols = 96 chars + 1 leftover = 97 ✓
# Or: some lines are 12, some are 13 → 8 × 12 + n × 1 = 97

# Try 8-line layouts
for extra_on_line in range(9):  # which lines get extra char
    # "8 lines, 73 remaining" → hmm, or "8 lines then 73 chars" → 8+73=81? not 97
    # OR: K4 is laid in rows, with row widths: 8 rows × (97/8 ≈ 12)
    # 12 + 12 + 12 + 12 + 12 + 12 + 12 + 13 = 97 or various distributions
    pass

# Most natural: 8 lines × 12 = 96, + 1 = 97
# Row widths: 7 rows of 12, 1 row of 13 → total 97
# But "8 lines 73" might mean something else entirely

# Try: 8 and 73 as keys for specific columnar transpositions
for W_8 in [8]:
    for n_K4 in [73]:  # treat 73 as the "long section" length
        # Layout: first 73 chars in W_8 columns, last 24 separately
        # Actually "8 lines, 73" might mean: line width is 73/8? No...
        # "8 lines" → 8 rows. Total = 97 → avg 12.1 chars/row
        # "73" could be: chars in some sub-block, or a key value

        # Interpretation: lay K4 in 8 rows (partial last row), permute columns
        W_actual = math.ceil(97/8)  # = 13
        perm_8 = make_columnar_perm([0,1,2,3,4,5,6,7,8,9,10,11,12], W_actual)
        if perm_8:
            test_perm(perm_8, f'lines8_natural', verbose=True)

        # If "73" means col width 73 (just 1 column with 73 chars + another with 24)
        # → columnar with key "KR" or similar 2-letter key?
        for two_col_key in ['KR', 'YP', 'PT', 'TO', 'OS', 'SA', 'TK', 'KT']:
            p = keyword_columnar_perm(two_col_key, 97)
            if p:
                test_perm(p, f'lines8_73_{two_col_key}', verbose=True)

# The most promising "8 lines 73" interpretation:
# 97 = 24 + 73 → first 24 chars form one block, last 73 form another
# Swap the two blocks
perm_swap = list(range(24, 97)) + list(range(0, 24))  # last 73 first, then first 24
if is_valid_perm(perm_swap):
    test_perm(perm_swap, '8lines73_swap_24_73', verbose=True)
    test_reverse_composition(perm_swap, '8lines73_swap_24_73')

perm_swap2 = list(range(73, 97)) + list(range(0, 73))  # last 24 first, then first 73
if is_valid_perm(perm_swap2):
    test_perm(perm_swap2, '8lines73_swap_73_24', verbose=True)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7: T-position combined with grille-extract arithmetic
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 7: Extract × T-position arithmetic ═══")

# For each K4 position i, compute: (extract_ka[i] * T_KA_idx) % 97
extract_ka = [KA.index(c) for c in GRILLE_EXTRACT[:97]]
T_KA_idx = 4

for op_name, op_fn in [
    ("mul_T", lambda i: (extract_ka[i] * T_KA_idx) % 97),
    ("add_T", lambda i: (extract_ka[i] + T_KA_idx) % 26),
    ("xor_T", lambda i: extract_ka[i] ^ T_KA_idx),
    ("pow_T", lambda i: pow(extract_ka[i] + 1, T_KA_idx, 97)),  # modular exponentiation
    ("mix", lambda i: (extract_ka[i] * (T_KA_idx + i)) % 97),
    ("tdiff", lambda i: abs(extract_ka[i] - T_KA_idx)),
]:
    vals = [op_fn(i) for i in range(97)]
    if len(set(vals)) == 97:
        res = test_perm(vals, f'S7_perm_{op_name}', verbose=True)
    else:
        perm_r = stable_rank(vals)
        if is_valid_perm(perm_r):
            res = test_perm(perm_r, f'S7_rank_{op_name}', verbose=True)
            if res and res[0] > SCORE_THRESHOLD:
                print(f"  S7_rank_{op_name}: {res[0]:.2f}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8: The missing T as a positional INVERTER
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 8: T as positional inverter/mirror ═══")

# "T is your position" → for every K4[i] that maps to T under some key,
# that position i is "marked" and the surrounding chars are inverted/mirrored

# Find all K4 positions where Vig(K4[i], kw[i%L]) = T for each keyword kw
for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW']:
    t_positions = [i for i in range(97) if AZ.find(K4[i]) >= 0 and
                   vig_dec(K4[i], kw[i % len(kw)]) == 'T']
    print(f"  Positions where Vig(K4,{kw})=T: {t_positions[:10]}...")
    if len(t_positions) == 4 or len(t_positions) == 5:
        print(f"    *** Interesting: {len(t_positions)} T-positions = same as T-holes!")
        # Use these as segment boundaries
        t_pos_sorted = sorted(t_positions)
        segs_auto = []
        prev = 0
        for tp in t_pos_sorted:
            segs_auto.append(list(range(prev, tp)))
            prev = tp + 1
        segs_auto.append(list(range(prev, 97)))
        # Try all permutations of these segments
        for seg_perm in itertools.permutations(range(len(segs_auto))):
            perm_auto = []
            for si in seg_perm:
                perm_auto.extend(segs_auto[si])
            if is_valid_perm(perm_auto, 97):
                test_perm(perm_auto, f'S8_tpositions_{kw}_segs_{"".join(str(s) for s in seg_perm)}')

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9: Grille as rectangular route cipher key
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 9: Rectangular route cipher reads ═══")

# Lay K4 in various rectangle shapes, read in alternative routes
for rows, cols in [(7,14), (14,7), (97,1), (1,97), (13,8), (8,13),
                   (4,25), (25,4), (5,20), (20,5), (6,17), (17,6)]:
    if rows * cols < 97: continue
    # Standard routes: row, column, diagonal, zigzag
    for route in ['rows_LR', 'rows_RL', 'cols_TD', 'cols_BU',
                  'boustro_LR', 'boustro_TD']:
        perm = []
        if route == 'rows_LR':
            for r in range(rows):
                for c in range(cols):
                    pos = r * cols + c
                    if pos < 97: perm.append(pos)
        elif route == 'rows_RL':
            for r in range(rows):
                for c in range(cols-1, -1, -1):
                    pos = r * cols + c
                    if pos < 97: perm.append(pos)
        elif route == 'cols_TD':
            for c in range(cols):
                for r in range(rows):
                    pos = r * cols + c
                    if pos < 97: perm.append(pos)
        elif route == 'cols_BU':
            for c in range(cols):
                for r in range(rows-1, -1, -1):
                    pos = r * cols + c
                    if pos < 97: perm.append(pos)
        elif route == 'boustro_LR':
            for r in range(rows):
                if r % 2 == 0:
                    for c in range(cols):
                        pos = r*cols+c
                        if pos < 97: perm.append(pos)
                else:
                    for c in range(cols-1,-1,-1):
                        pos = r*cols+c
                        if pos < 97: perm.append(pos)
        elif route == 'boustro_TD':
            for c in range(cols):
                if c % 2 == 0:
                    for r in range(rows):
                        pos = r*cols+c
                        if pos < 97: perm.append(pos)
                else:
                    for r in range(rows-1,-1,-1):
                        pos = r*cols+c
                        if pos < 97: perm.append(pos)

        if is_valid_perm(perm, 97):
            test_perm(perm, f'S9_route_{rows}x{cols}_{route}')

print(f"  Tested rectangle route permutations")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10: The "try both 97/98 chars" hint → extended K4 approaches
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 10: 97 vs 98 char consideration ═══")
# KryptosFan notes: 'try both' 97/98 chars
# Perhaps a NULL char should be inserted somewhere → K4 becomes 98 chars?

# Hypothesis: K4 should have 98 chars (one was dropped)
# Try inserting a null/filler at each of 97+1 positions
for insert_pos in range(0, 98, 10):  # sample every 10th position
    for insert_char in ['X', 'A', 'E', 'T', 'Z']:
        k4_extended = K4[:insert_pos] + insert_char + K4[insert_pos:]
        assert len(k4_extended) == 98
        # Now try keyed columnar on 98 chars (7×14 grid is clean for 98!)
        p98 = keyword_columnar_perm('KRYPTOS', 98)
        if p98:
            ct98 = apply_perm(k4_extended, p98)
            pt98 = vig_dec(ct98[:97], 'KRYPTOS', AZ)  # take first 97 of result
            if pt98:
                sc = qgscore(pt98)
                ene = pt98.find(CRIB1); bc = pt98.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT [98char/ins{insert_pos}/{insert_char}]: ENE@{ene} BC@{bc}")
                    print(f"    PT: {pt98}")
                if sc > SCORE_THRESHOLD:
                    print(f"  98char_ins{insert_pos}_{insert_char}: score={sc:.2f}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11: T-hole positions as Polybius/VIC coordinates
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 11: VIC-style cipher using T-hole coordinates ═══")

# T-holes at (row, col) in the grille: (7,23), (12,18), (23,7), (3,27)
# (For reading-order indices 21, 33, 90, 12)
t_hole_coords = [HOLES[i] for i in sorted(t4_indices)]
print(f"T-hole coordinates: {t_hole_coords}")

# Use coordinates as digits in VIC-style straddling checkerboard
for (r, c) in t_hole_coords:
    for val in [r, c, r+c, r*c%26, r*c%97, abs(r-c)]:
        print(f"  ({r},{c}): r={r} c={c} r+c={r+c} r*c%26={r*c%26}")
    break  # just show first one

# T-hole (row, col) pairs as modular key
t_coords_flat = [v for r,c in t_hole_coords for v in [r,c]]
print(f"T-hole coords flat: {t_coords_flat}")  # 8 values

# Use these 8 values as a Vig key (cycle through them)
key_from_coords_az = ''.join(AZ[v % 26] for v in t_coords_flat)
key_from_coords_ka = ''.join(KA[v % 26] for v in t_coords_flat)
print(f"AZ key from T-coords: {key_from_coords_az}")
print(f"KA key from T-coords: {key_from_coords_ka}")

for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
    for alpha_name, alpha, key_str in [
        ("AZ", AZ, key_from_coords_az),
        ("KA", KA, key_from_coords_ka),
    ]:
        pt = fn(K4, key_str, alpha)
        if pt:
            sc = qgscore(pt)
            ene = pt.find(CRIB1); bc = pt.find(CRIB2)
            if ene >= 0 or bc >= 0:
                print(f"\n*** CRIB HIT [S11_VIC/{cipher_name}/{alpha_name}]: ENE@{ene} BC@{bc}")
                print(f"    key: {key_str}")
                print(f"    PT: {pt}")
            if sc > SCORE_THRESHOLD:
                print(f"  S11_{cipher_name}_{alpha_name}: score={sc:.2f}")

# ── Final Summary ─────────────────────────────────────────────────────────────
print(f"\n═══ FINAL SUMMARY ═══")
print(f"Total unique permutations tested: {len(tested_perms)}")
print(f"Total RESULTS stored: {len(RESULTS)}")

if RESULTS:
    RESULTS.sort(key=lambda x: -x['score'])
    print(f"\nTop results:")
    seen = set()
    for r in RESULTS[:20]:
        k = f"{r['name']}_{r.get('key','')}_{r.get('cipher','')}_{r.get('alpha','')}"
        if k in seen: continue
        seen.add(k)
        crib = f"ENE@{r['pt'].find(CRIB1)}" if r['pt'].find(CRIB1)>=0 else ""
        crib += f" BC@{r['pt'].find(CRIB2)}" if r['pt'].find(CRIB2)>=0 else ""
        print(f"  {r['score']:.2f} [{r['name']}] {crib}")
        print(f"       PT: {r['pt'][:60]}...")

    with open(f'{OUT_DIR}/final_results.json', 'w') as f:
        json.dump(RESULTS[:30], f, indent=2)
    print(f"\nSaved to {OUT_DIR}/final_results.json")
else:
    print("No results above threshold (-600).")

print("\nDone!")
