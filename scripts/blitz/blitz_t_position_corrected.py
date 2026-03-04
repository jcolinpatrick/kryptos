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
blitz_t_position_corrected.py — T-position exploitation with CORRECTED T-column formula.

KEY CORRECTIONS from previous analysis:
  1. T appears at hole (r,c) when (c+r)%26 = 4, NOT just when c=(4-r)%26
     → The alphabet WRAPS in the physical grid (columns 26-32 repeat 0-5)
     → 4 holes produce T (at indices 12, 21, 33, 90 in reading order)

  2. Column offset k=2 or k=3 gives ZERO T-diagonal hits, explaining T's absence.
     This means physical column k is KA[0], so letter at (r,c) is KA[(c-k+r)%26].

  3. The CORRECT tableau letter at hole (r,c) with offset k is KA[(c-k+r)%26]
     (vs. the buggy KA[(c+r)%26] used in script 2)

This script:
  - Uses k=2 and k=3 (zero T-hit offsets) for ALL T-position calculations
  - Computes correct T-columns, distances, and offsets
  - Tries ALL approaches A-T with corrected formulas
  - Also explores what the 4-T-position structure implies
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
KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
            'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA',
            'LAYER','ILLUSION','IQLUSION']

OUT_DIR = 'blitz_results/t_position'
os.makedirs(OUT_DIR, exist_ok=True)

qg = json.load(open('data/english_quadgrams.json'))
def qgscore(text):
    return sum(qg.get(text[i:i+4].upper(), -10.0) for i in range(len(text)-3))

# Score per quadgram: good English ~-4 to -5, random ~-10
# Total for 94 quadgrams: good -376 to -470, random -940
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
print(f"Loaded {len(HOLES)} holes")

# Verify T-positions with correct formula: T at hole (r,c) when (c+r)%26 = 4
t_holes_correct = [(i, r, c) for i,(r,c) in enumerate(HOLES) if (c+r)%26 == 4]
print(f"\nT-positions (correct, (c+r)%26=4): {len(t_holes_correct)} hits")
for i, r, c in t_holes_correct:
    print(f"  hole[{i}] = ({r},{c}): (c+r)%26 = {(c+r)%26} = T = KA[4]")

# With offset k: T at (r,c) when (c-k+r)%26 = 4
print(f"\nColumn offsets with 0 T-hits:")
valid_offsets = []
for k in range(33):
    hits = [(i,r,c) for i,(r,c) in enumerate(HOLES) if (c-k+r)%26 == 4]
    if len(hits) == 0:
        valid_offsets.append(k)
        print(f"  k={k}: T-col for row 0 = {k+4}, rows [4,3,2,1,0,25,...] shifted by k")

print(f"\nValid offsets (0 T-hits): {valid_offsets}")

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

def test_perm(perm, name="unnamed", verbose=True):
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
                    print(f"    candidate CT: {candidate_ct}")
                    print(f"    PT: {pt}")
                    print(f"    Score: {sc:.2f}")
                    print(f"{'='*70}\n")
                    RESULTS.append((sc, name, list(perm), pt, kw, cipher_name, alpha_name, candidate_ct))
                if best is None or sc > best[0]:
                    best = (sc, name, list(perm), pt, kw, cipher_name, alpha_name, candidate_ct)
    if best and best[0] > SCORE_THRESHOLD:
        RESULTS.append(best)
        if verbose:
            print(f"  {name}: {best[0]:.2f} [{best[4]}/{best[5]}/{best[6]}]")
    return best

# ══════════════════════════════════════════════════════════════════════════════
# For each valid offset k, run the full suite of T-position approaches
# ══════════════════════════════════════════════════════════════════════════════

for K_OFFSET in valid_offsets[:6]:  # try first 6 valid offsets
    print(f"\n{'='*70}")
    print(f"OFFSET k={K_OFFSET}: letter at (r,c) = KA[(c - {K_OFFSET} + r) % 26]")
    print(f"  T-column in row r: physical col = {K_OFFSET} + (4-r)%26")
    print(f"{'='*70}")

    def t_col_k(r):
        """Physical column of T in row r with offset k."""
        return K_OFFSET + (4 - r) % 26

    def letter_at(r, c):
        """Letter at physical position (r,c) in KA tableau with offset k."""
        return KA[(c - K_OFFSET + r) % 26]

    def t_dist_k(r, c):
        """Distance from hole (r,c) to T-column for row r."""
        tc = t_col_k(r)
        # T also wraps: if tc > 32, use tc % 26 + K_OFFSET... complex
        # Simplest: distance to nearest T column (accounting for alphabet wrap)
        # T columns in row r: K_OFFSET + (4-r)%26, K_OFFSET + (4-r)%26 + 26, ...
        d = abs(c - tc)
        d2 = abs(c - (tc + 26)) if tc + 26 <= 32 else d
        d3 = abs(c - (tc - 26)) if tc - 26 >= 0 else d
        return min(d, d2, d3)

    def t_offset_k(r, c):
        """T-relative offset: (col - T_col) in the alphabet space."""
        # The letter at (r,c) is KA[(c-K_OFFSET+r)%26]
        # T is KA[4], so the "distance from T" in alphabet space is:
        return (c - K_OFFSET + r - 4) % 26  # = KA-index of letter at (r,c) - 4

    # Compute T-distances and offsets for all 107 holes
    t_dists = [t_dist_k(r, c) for (r,c) in HOLES]
    t_offsets = [t_offset_k(r, c) for (r,c) in HOLES]
    letters = [letter_at(r, c) for (r,c) in HOLES]  # letters at each hole with offset k

    # Verify: no T in letters
    t_count = letters.count('T')
    if t_count > 0:
        print(f"  WARNING: {t_count} T's in letters! (should be 0 for offset k={K_OFFSET})")
        continue
    print(f"  Verified: 0 T's in {len(letters)} hole letters ✓")

    # Show the corrected extract (should match GRILLE_EXTRACT if we sorted correctly)
    corrected_extract = ''.join(letters)
    print(f"  Extract from k={K_OFFSET}: {corrected_extract[:30]}...")
    print(f"  Original grille extract:  {GRILLE_EXTRACT[:30]}...")

    # Are they the same?
    if corrected_extract[:106] == GRILLE_EXTRACT[:106]:
        print(f"  ✓ MATCHES original extract!")
    elif sorted(corrected_extract) == sorted(GRILLE_EXTRACT):
        print(f"  ✓ Same multiset, different order (permuted)")
    else:
        # Count differences
        diffs = sum(1 for a,b in zip(corrected_extract, GRILLE_EXTRACT) if a != b)
        print(f"  {diffs} chars differ from original extract")

    # The key insight: with offset k, the CORRECTED T-distances/offsets
    # For the 97-hole sequence, compute rank permutation

    # ── Approach B (corrected): Sort by T-distance ────────────────────────────
    for sort_desc, key_fn in [
        ("tdist_asc", lambda i: (t_dists[i], i)),
        ("tdist_desc", lambda i: (-t_dists[i], i)),
        ("toffset_asc", lambda i: (t_offsets[i], i)),
        ("toffset_desc", lambda i: (-t_offsets[i], i)),
        ("letter_rank", lambda i: (KA.index(letters[i]) if letters[i] in KA else 99, i)),
    ]:
        ordered = sorted(range(107), key=key_fn)
        first97 = [p for p in ordered[:97] if p < 97]
        if len(first97) == 97 and len(set(first97)) == 97:
            test_perm(first97, f'k{K_OFFSET}_B_{sort_desc}', verbose=True)

    # ── Approach C (corrected): T-offset as columnar key ─────────────────────
    for W in [7, 8, 13, 14, 26, 28]:
        col_key = t_offsets[:W]
        col_order = sorted(range(W), key=lambda c: (col_key[c], c))
        n_rows_g = math.ceil(97/W)
        perm = []
        for c in col_order:
            for r_idx in range(n_rows_g):
                idx = r_idx * W + c
                if idx < 97: perm.append(idx)
        if is_valid_perm(perm):
            test_perm(perm, f'k{K_OFFSET}_C_toffset_col_W{W}', verbose=True)
            test_perm(invert_perm(perm), f'k{K_OFFSET}_C_toffset_col_inv_W{W}', verbose=True)

    # ── Approach G (corrected): Tableau letters as key ────────────────────────
    # letter[i] is the letter at hole i with offset k → use as running key
    key97_letters = ''.join(letters[:97])
    print(f"\n  k={K_OFFSET} tableau key (97 chars): {key97_letters}")

    for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            pt = fn(K4, key97_letters, alpha)
            if pt:
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT [k{K_OFFSET}_tableau_key/{cipher_name}/{alpha_name}]: ENE@{ene} BC@{bc}")
                    print(f"    key: {key97_letters}")
                    print(f"    PT: {pt}")
                if sc > SCORE_THRESHOLD:
                    print(f"  k{K_OFFSET}_tableau_key_{cipher_name}_{alpha_name}: score={sc:.2f}")

    # Try sliding windows of key (all 107 holes → select 97)
    for start in range(11):
        key_sel = ''.join(letters[start:start+97])
        if len(key_sel) != 97: continue
        for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, key_sel, AZ)
            if pt:
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT [k{K_OFFSET}_tableau_key_s{start}/{cipher_name}]: ENE@{ene} BC@{bc}")
                    print(f"    key: {key_sel}")
                    print(f"    PT: {pt}")
                if sc > SCORE_THRESHOLD:
                    print(f"  k{K_OFFSET}_sel{start}_{cipher_name}: score={sc:.2f}")

    # ── Corrected T-column key (26 or 28 values) as Vig/Beau key ─────────────
    for n_rows_key in [26, 28]:
        t_col_key = ''.join(AZ[t_col_k(r) % 26] for r in range(n_rows_key))
        t_col_key_ka = ''.join(KA[t_col_k(r) % 26] for r in range(n_rows_key))
        for key_alpha, key_str in [("AZ", t_col_key), ("KA", t_col_key_ka)]:
            for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(K4, key_str, AZ)
                if pt:
                    sc = qgscore(pt)
                    ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                    if ene >= 0 or bc >= 0:
                        print(f"\n*** CRIB HIT [k{K_OFFSET}_tcol_key/{key_alpha}/{cipher_name}]: ENE@{ene} BC@{bc}")
                        print(f"    key: {key_str}")
                        print(f"    PT: {pt}")
                    if sc > SCORE_THRESHOLD:
                        print(f"  k{K_OFFSET}_tcol_key_{key_alpha}_{cipher_name}: score={sc:.2f}")

    # ── T-distance as direct rank permutation (the core approach) ─────────────
    # Rank by T-distance: closest hole gets K4[0], farthest gets K4[96]
    perm_tdist_rank = stable_rank(t_dists[:97])
    test_perm(perm_tdist_rank, f'k{K_OFFSET}_tdist_rank', verbose=True)
    test_perm(invert_perm(perm_tdist_rank), f'k{K_OFFSET}_tdist_rank_inv', verbose=True)

    perm_toff_rank = stable_rank(t_offsets[:97])
    test_perm(perm_toff_rank, f'k{K_OFFSET}_toffset_rank', verbose=True)
    test_perm(invert_perm(perm_toff_rank), f'k{K_OFFSET}_toffset_rank_inv', verbose=True)

    # ── Two-region split by T-boundary ────────────────────────────────────────
    left_k  = [i for i,(r,c) in enumerate(HOLES[:97]) if c < t_col_k(r)]
    right_k = [i for i,(r,c) in enumerate(HOLES[:97]) if c > t_col_k(r)]
    on_k    = [i for i,(r,c) in enumerate(HOLES[:97]) if c == t_col_k(r)]
    print(f"  k={K_OFFSET}: left={len(left_k)}, right={len(right_k)}, on-T={len(on_k)}")

    for desc, order in [
        ("left_right", left_k + right_k),
        ("right_left", right_k + left_k),
    ]:
        if len(order) == 97 and len(set(order)) == 97:
            test_perm(order, f'k{K_OFFSET}_D_{desc}', verbose=True)

    # ── T-count per row as group sorting key ──────────────────────────────────
    # For each hole, compute how many rows above it have T in a column ≤ its col
    def t_count_k(r, c):
        """T's appearing before (r,c) in reading order with offset k."""
        count = r  # T's in rows 0..r-1 (one per row)
        tc_r = t_col_k(r)
        if c > tc_r:
            count += 1
        return count

    t_counts_k = [t_count_k(r, c) for (r,c) in HOLES[:97]]
    perm_tcount_k = stable_rank(t_counts_k)
    test_perm(perm_tcount_k, f'k{K_OFFSET}_tcount_rank', verbose=True)

    # Columnar with t-counts
    for W in [7, 8, 13, 14, 26, 28]:
        col_key_tc = t_counts_k[:W]
        col_order_tc = sorted(range(W), key=lambda c: (col_key_tc[c], c))
        n_rows_g = math.ceil(97/W)
        perm_tc = []
        for c in col_order_tc:
            for r_idx in range(n_rows_g):
                idx = r_idx * W + c
                if idx < 97: perm_tc.append(idx)
        if is_valid_perm(perm_tc):
            test_perm(perm_tc, f'k{K_OFFSET}_tcount_col_W{W}', verbose=True)

    # ── T-offset as alphabet position → Vigenère key ─────────────────────────
    # The T-offset gives how far each hole is from T in alphabet space
    # Map offsets to letters and use as Vig key
    key_from_toffset_az = ''.join(AZ[t_offsets[i] % 26] for i in range(97))
    key_from_toffset_ka = ''.join(KA[t_offsets[i] % 26] for i in range(97))

    for alpha_name, key_str in [("AZ", key_from_toffset_az), ("KA", key_from_toffset_ka)]:
        for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, key_str, AZ)
            if pt:
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT [k{K_OFFSET}_toff_as_key/{alpha_name}/{cipher_name}]: ENE@{ene} BC@{bc}")
                    print(f"    key: {key_str[:30]}...")
                    print(f"    PT: {pt}")
                if sc > SCORE_THRESHOLD:
                    print(f"  k{K_OFFSET}_toff_as_key_{alpha_name}_{cipher_name}: score={sc:.2f}")

    # ── "T is your position" with corrected alphabet ───────────────────────────
    # With offset k, T's KA-index is 4. The letter at hole i is letters[i].
    # "T is your position" → for each K4 char, find key that gives PT=T
    # That key, when applied to K4, gives T. The KEY is position-encoded.
    T_KA_idx = 4  # T = KA[4]
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        T_idx = alpha.index('T')
        key_vig_T = ''.join(alpha[(alpha.index(c) - T_idx) % 26] for c in K4)
        key_beau_T = ''.join(alpha[(T_idx + alpha.index(c)) % 26] for c in K4)

        # Compare with corrected tableau letters: does key_vig_T match letters97?
        match_vig = sum(1 for a,b in zip(key_vig_T, ''.join(letters[:97])) if a==b)
        match_beau = sum(1 for a,b in zip(key_beau_T, ''.join(letters[:97])) if a==b)
        print(f"\n  k={K_OFFSET} T-position key vs corrected letters:")
        print(f"    Vig  key: {key_vig_T[:30]}...")
        print(f"    Beau key: {key_beau_T[:30]}...")
        print(f"    Letters:  {''.join(letters[:30])}...")
        print(f"    Vig match: {match_vig}/97, Beau match: {match_beau}/97")

        # If high match → we have a structural connection!

        # Use key as columnar transposition key
        for mode_name, key_str in [("vig_T_key", key_vig_T), ("beau_T_key", key_beau_T)]:
            # Rank-based permutation
            key_nums = [alpha.index(c) for c in key_str]
            perm_rank = stable_rank(key_nums)
            if is_valid_perm(perm_rank):
                test_perm(perm_rank, f'k{K_OFFSET}_G_{alpha_name}_{mode_name}_rank', verbose=True)
                test_perm(invert_perm(perm_rank), f'k{K_OFFSET}_G_{alpha_name}_{mode_name}_rank_inv', verbose=True)

# ══════════════════════════════════════════════════════════════════════════════
# SPECIAL SECTION: Full 107-char sequence with k=0 T-holes (indices 12,21,33,90)
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SPECIAL: Full 107-char with T at indices [12,21,33,90] ═══")

# Reconstruct full sequence including T's at correct positions
t_indices_correct = [i for i,(r,c) in enumerate(HOLES) if (c+r)%26 == 4]
print(f"T-hole indices (k=0 correct formula): {t_indices_correct}")

full107_correct = []
extract_iter = iter(GRILLE_EXTRACT)
for i in range(107):
    if i in set(t_indices_correct):
        full107_correct.append('T')
    else:
        full107_correct.append(next(extract_iter, '?'))

print(f"Full 107-char: {''.join(full107_correct)}")
print(f"T positions: {[i for i,c in enumerate(full107_correct) if c=='T']}")

# These 4 T-positions (12, 21, 33, 90) divide the 107-char sequence into 5 parts:
# [0:12], [13:21], [22:33], [34:90], [91:107] (including T at boundaries)
t_indices_set = set(t_indices_correct)
non_t_indices = [i for i in range(107) if i not in t_indices_set]  # 103 non-T holes

print(f"\n103 non-T hole positions (first 20): {non_t_indices[:20]}...")

# These 103 non-T holes in reading order give 103 values
# We need 97 from these 103 (drop 6)
# The 4 T-holes (12, 21, 33, 90) are special anchors

# Method 1: Take first 97 non-T holes (indices 0-102 of non_t_indices)
first97_nonT = non_t_indices[:97]
if len(set(first97_nonT)) == 97 and all(p < 97 for p in first97_nonT):
    res = test_perm(first97_nonT, 'full107_first97_nonT', verbose=True)

# Method 2: Use T-positions as "skip" markers: when we encounter a T,
# skip the next K4 char
# → Output positions at non-T slots, but skip K4 positions corresponding to T-anchor slots
perm_skip = [p for p in range(97) if p not in t_indices_set][:97]
if len(perm_skip) == 93:  # if exactly 4 T-indices are in 0..96
    # Need to fill 4 more positions somehow
    extras = [p for p in range(97) if p not in set(perm_skip)]
    perm_skip_full = perm_skip + extras
    if is_valid_perm(perm_skip_full):
        test_perm(perm_skip_full, 'full107_skip_T_positions', verbose=True)

# Method 3: Sort 107-hole indices by full107_correct value (T has special sorting)
# T = KA[4], other chars sort by KA-index
ka_sort_values = []
for i, ch in enumerate(full107_correct):
    if ch == 'T':
        ka_sort_values.append(4)
    elif ch in KA:
        ka_sort_values.append(KA.index(ch))
    else:
        ka_sort_values.append(99)

ordered_full = sorted(range(107), key=lambda i: (ka_sort_values[i], i))
# Select 97 of these
for sel_name, sel in [
    ('first97', ordered_full[:97]),
    ('last97', ordered_full[10:]),
    ('skip_T', [p for p in ordered_full if p not in t_indices_set][:97]),
]:
    s = sel[:97] if len(sel) > 97 else sel
    valid = [p for p in s if p < 97]
    if len(valid) == 97 and len(set(valid)) == 97:
        test_perm(valid, f'full107_sorted_{sel_name}', verbose=True)

# ══════════════════════════════════════════════════════════════════════════════
# SPECIAL SECTION: Test ALL KEYWORDS directly as running keys
# (sanity check: make sure the framework is working)
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SANITY: Test known keywords on K4 directly ═══")
for kw in KEYWORDS:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, kw, alpha)
            if pt:
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"  SANITY CRIB HIT: {kw}/{cipher_name}/{alpha_name}: ENE@{ene} BC@{bc}")
                    print(f"    PT: {pt}")
                if sc > -500:
                    print(f"  {kw}/{cipher_name}/{alpha_name}: score={sc:.2f}")

# ══════════════════════════════════════════════════════════════════════════════
# NOVEL: Use 4 T-positions as quarter-points for a 4-segment permutation
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ NOVEL: 4 T-holes as quarter-point permutation markers ═══")

# T-holes at positions 12, 21, 33, 90 of 107
# These divide [0..96] (K4 positions) into segments:
# K4[0..12-1] = K4[0..11] → 12 chars → "before first T"
# K4[12..21-1] = K4[12..20] → 9 chars → "between T1 and T2"
# K4[21..33-1] = K4[21..32] → 12 chars → "between T2 and T3"
# K4[33..90-1] = K4[33..89] → 57 chars → "between T3 and T4"
# K4[90..96] = 7 chars → "after T4"

t4 = sorted([i for i,(r,c) in enumerate(HOLES) if (c+r)%26==4 and i<97])
print(f"T-positions in first 97 holes: {t4}")  # should be [12, 21, 33, 90]

if t4 == [12, 21, 33, 90]:
    # Segment boundaries
    segs_k4 = [
        list(range(0, 12)),      # 12 chars (before hole-12)
        list(range(12, 21)),     # 9 chars (from hole-12 to hole-21)
        list(range(21, 33)),     # 12 chars (from hole-21 to hole-33)
        list(range(33, 90)),     # 57 chars (from hole-33 to hole-90)
        list(range(90, 97)),     # 7 chars (from hole-90 to end)
    ]
    print(f"K4 segments: {[len(s) for s in segs_k4]} chars")

    # Try all 120 orderings of the 5 segments
    count_tested = 0
    for seg_perm in itertools.permutations(range(5)):
        ordered = []
        for si in seg_perm:
            ordered.extend(segs_k4[si])
        if is_valid_perm(ordered):
            test_perm(ordered, f'T4_segs_{"".join(str(s) for s in seg_perm)}',
                     verbose=False)
            count_tested += 1

    print(f"  Tested {count_tested} segment permutations")

    # Also try segment reversal
    for seg_perm in itertools.permutations(range(5)):
        for reverse_mask in range(32):  # 2^5 reversals
            ordered = []
            for idx, si in enumerate(seg_perm):
                seg = segs_k4[si][:]
                if (reverse_mask >> idx) & 1:
                    seg = list(reversed(seg))
                ordered.extend(seg)
            if is_valid_perm(ordered):
                test_perm(ordered, f'T4_segs_rev_{seg_perm}_{reverse_mask:05b}',
                         verbose=False)

    print(f"  Tested all 120×32=3840 segment-with-reversal permutations")

# ══════════════════════════════════════════════════════════════════════════════
# NOVEL: T-holes as bit flags — select/exclude adjacent positions
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ NOVEL: T-holes as selection flags ═══")

# For each T-hole at position t in the 107-hole sequence:
# It signals: "the next N holes form a group" or "skip these" or "reverse these"
for window_size in [1, 2, 3, 4, 5, 6, 7]:
    # Method: After each T-hole, reverse the next window_size holes
    perm = list(range(97))
    for t_idx in sorted(t4, reverse=True):  # apply from rightmost first
        win_start = t_idx + 1
        win_end   = min(win_start + window_size, 97)
        if win_end > win_start:
            perm[win_start:win_end] = reversed(perm[win_start:win_end])
    if is_valid_perm(perm):
        test_perm(perm, f'T4_after_T_reverse_W{window_size}', verbose=True)

    # Method: Before each T-hole, reverse the previous window_size holes
    perm2 = list(range(97))
    for t_idx in sorted(t4):  # apply from leftmost first
        win_end   = t_idx
        win_start = max(0, win_end - window_size)
        if win_end > win_start:
            perm2[win_start:win_end] = reversed(perm2[win_start:win_end])
    if is_valid_perm(perm2):
        test_perm(perm2, f'T4_before_T_reverse_W{window_size}', verbose=True)

# ══════════════════════════════════════════════════════════════════════════════
# NOVEL: T-holes as crossover points for two interleaved streams
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ NOVEL: T-holes as crossover/interleave points ═══")

# Theory: K4 is composed of two interleaved streams, and T-holes mark where
# the streams swap. Stream A and Stream B alternate with crossovers at T-holes.
# Deinterleave at T-crossover points to get real CT.

t4_ext = [0] + t4 + [97]  # add boundary points
stream_A = []
stream_B = []
for seg_idx in range(len(t4_ext) - 1):
    seg_start = t4_ext[seg_idx]
    seg_end   = t4_ext[seg_idx + 1]
    seg = list(range(seg_start, seg_end))
    if seg_idx % 2 == 0:
        stream_A.extend(seg)
    else:
        stream_B.extend(seg)

print(f"Stream A ({len(stream_A)} chars): {stream_A[:10]}...")
print(f"Stream B ({len(stream_B)} chars): {stream_B[:10]}...")

# Reconstruct by: interleave A and B differently
for desc, perm in [
    ("A_then_B", stream_A + stream_B),
    ("B_then_A", stream_B + stream_A),
    ("interleave_AB", [x for pair in itertools.zip_longest(stream_A, stream_B) for x in pair if x is not None]),
    ("interleave_BA", [x for pair in itertools.zip_longest(stream_B, stream_A) for x in pair if x is not None]),
]:
    perm97 = perm[:97] if len(perm) >= 97 else perm
    if is_valid_perm(perm97):
        test_perm(perm97, f'T4_stream_{desc}', verbose=True)

# ══════════════════════════════════════════════════════════════════════════════
# NOVEL: Use T-hole positions to define a "book cipher" style index into K4
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ NOVEL: T-hole arithmetic as indexing ═══")

# T-positions are 12, 21, 33, 90. Their differences are: 9, 12, 57.
# These might encode something:
t_diffs = [t4[i+1] - t4[i] for i in range(len(t4)-1)]
t_diffs2 = [t4[0]] + t_diffs + [97 - t4[-1]]  # include start and end distances
print(f"T-hole positions: {t4}")
print(f"T-hole differences: {t_diffs} (then to end: {97 - t4[-1]})")
print(f"Full differences (incl. start/end): {t_diffs2}")

# Sum of t_diffs2: should be 97
print(f"Sum: {sum(t_diffs2)} (should be 97)")

# Use differences as column widths for columnar transposition
if sum(t_diffs2) == 97:
    # [12, 9, 12, 57, 7] as column widths
    col_widths = t_diffs2
    print(f"Using {col_widths} as column widths for irregular columnar transposition")

    # Build permutation: read off columns (width-by-width)
    # First, lay K4 in these column widths (left-to-right)
    # Then permute the groups
    groups = []
    pos = 0
    for w in col_widths:
        groups.append(list(range(pos, pos+w)))
        pos += w

    for seg_perm in itertools.permutations(range(len(groups))):
        perm_irreg = []
        for si in seg_perm:
            perm_irreg.extend(groups[si])
        if is_valid_perm(perm_irreg, 97):
            test_perm(perm_irreg, f'T4_irregular_col_{"".join(str(s) for s in seg_perm)}',
                     verbose=False)
    print(f"  Tested {math.factorial(len(groups))} irregular columnar permutations")

# Also use t_diffs as key for standard columnar
for W_c in t_diffs:
    if W_c < 2: continue
    col_order_c = sorted(range(W_c), key=lambda c: c)  # simple ascending
    n_rows_c = math.ceil(97/W_c)
    perm_c = []
    for c in col_order_c:
        for r_idx in range(n_rows_c):
            idx = r_idx * W_c + c
            if idx < 97: perm_c.append(idx)
    if is_valid_perm(perm_c):
        test_perm(perm_c, f'T4_diff_col_W{W_c}', verbose=True)

# ── Final Summary ─────────────────────────────────────────────────────────────
print(f"\n═══ FINAL SUMMARY ═══")
print(f"Total unique permutations tested: {len(tested_perms)}")
if RESULTS:
    RESULTS.sort(key=lambda x: -x[0])
    print(f"\nTop results (score > {SCORE_THRESHOLD}):")
    seen = set()
    for r in RESULTS[:30]:
        sc, name, perm, pt, kw, cipher, alpha, candidate_ct = r
        key = f"{name}_{kw}_{cipher}_{alpha}"
        if key in seen: continue
        seen.add(key)
        ene = pt.find(CRIB1); bc = pt.find(CRIB2)
        crib_str = f"ENE@{ene}" if ene>=0 else ""
        crib_str += f" BC@{bc}" if bc>=0 else ""
        print(f"  {sc:.2f} [{name}] key={kw} {cipher}/{alpha} {crib_str}")
        print(f"       CT: {candidate_ct[:40]}...")
        print(f"       PT: {pt[:60]}...")

    with open(f'{OUT_DIR}/corrected_results.json', 'w') as f:
        json.dump([{"score": r[0], "name": r[1], "perm": r[2], "pt": r[3],
                    "key": r[4], "cipher": r[5], "alpha": r[6], "ct": r[7]}
                   for r in RESULTS[:30]], f, indent=2)
    print(f"\nSaved to {OUT_DIR}/corrected_results.json")
else:
    print("No results above threshold (-600).")

print("\nDone!")
