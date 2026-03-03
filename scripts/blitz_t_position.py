#!/usr/bin/env python3
"""
blitz_t_position.py — Exhaustive T-position exploitation for K4 unscrambling.

The Cardan grille extract (106 chars) is entirely MISSING the letter T.
P(chance) ≈ 1/69 — deliberate signal.

Paradigm: K4 carved text is SCRAMBLED ciphertext.
  PT → simple substitution → REAL CT → SCRAMBLE (transposition) → carved K4

Goal: find the permutation π s.t. apply_perm(K4, π) = REAL CT,
      which then decrypts with a short keyword (Vig or Beau).

Approaches A–G plus novel extensions.
"""

import sys, json, os, math, itertools
from collections import defaultdict, Counter

sys.path.insert(0, 'src')

# ── Constants ─────────────────────────────────────────────────────────────────
K4  = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA  = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
CRIB1 = "EASTNORTHEAST"
CRIB2 = "BERLINCLOCK"
KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
            'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA',
            'LAYER','ILLUSION','IQLUSION']
assert len(K4) == 97
assert len(GRILLE_EXTRACT) == 106
assert len(KA) == 26
assert 'T' not in GRILLE_EXTRACT, "T should be absent from extract!"

# Output dir
OUT_DIR = 'blitz_results/t_position'
os.makedirs(OUT_DIR, exist_ok=True)

# ── Load quadgrams ────────────────────────────────────────────────────────────
qg = json.load(open('data/english_quadgrams.json'))
def qgscore(text):
    return sum(qg.get(text[i:i+4].upper(), -10.0) for i in range(len(text)-3))

# ── Build correct hole list from authoritative mask ───────────────────────────
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

HOLES = []  # (row, col) 0-indexed
for r, line in enumerate(MASK_TEXT.strip().split('\n')):
    vals = line.split()
    for c, v in enumerate(vals):
        if v == '0':
            HOLES.append((r, c))

print(f"Parsed {len(HOLES)} holes from mask")
assert len(HOLES) == 107, f"Expected 107 holes, got {len(HOLES)}"

# ── KA tableau T-column per row ───────────────────────────────────────────────
# In row r, KA shifts left by r. T is at KA-index 4.
# T appears at column (4 - r) % 26 (within 0-indexed 26-char alphabet block).
def t_col(r):
    return (4 - r) % 26

T_COLS = [t_col(r) for r in range(28)]
print(f"T-columns for rows 0-27: {T_COLS}")

# ── Check: does any hole fall ON the T-diagonal? ─────────────────────────────
t_diagonal_hits = [(r, c) for (r, c) in HOLES if c == t_col(r)]
print(f"Holes ON T-diagonal: {len(t_diagonal_hits)} -> {t_diagonal_hits}")

# ── Utilities ─────────────────────────────────────────────────────────────────
def apply_perm(text, perm):
    """perm[i] = which K4 position goes to output position i"""
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
        ci = alpha.find(c)
        ki = alpha.find(key[i % len(key)])
        if ci < 0 or ki < 0: return None
        out.append(alpha[(ci - ki) % 26])
    return ''.join(out)

def beau_dec(ct, key, alpha=AZ):
    out = []
    for i,c in enumerate(ct):
        ci = alpha.find(c)
        ki = alpha.find(key[i % len(key)])
        if ci < 0 or ki < 0: return None
        out.append(alpha[(ki - ci) % 26])
    return ''.join(out)

RESULTS = []  # (score, name, perm, pt, key, cipher, alpha)

def test_perm(perm, name="unnamed"):
    """Test a permutation; return best result. Report crib hits immediately."""
    if not is_valid_perm(perm):
        return None
    candidate_ct = apply_perm(K4, perm)
    best = None
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(candidate_ct, kw, alpha)
                if pt is None: continue
                sc = qgscore(pt)
                ene = pt.find(CRIB1)
                bc  = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n{'='*60}")
                    print(f"*** CRIB HIT [{name}]: ENE@{ene} BC@{bc}")
                    print(f"    key={kw} cipher={cipher_name}/{alpha_name}")
                    print(f"    CT: {candidate_ct}")
                    print(f"    PT: {pt}")
                    print(f"    Score: {sc:.2f}")
                    print(f"{'='*60}\n")
                    RESULTS.append((sc, name, list(perm), pt, kw, cipher_name, alpha_name))
                if best is None or sc > best[0]:
                    best = (sc, name, list(perm), pt, kw, cipher_name, alpha_name)
    if best and best[0] > -7.5:  # track near-misses
        RESULTS.append(best)
    return best

def rank_to_perm(vals, n=97):
    """Convert a list of values (length n) to a rank-based permutation."""
    if len(vals) != n: return None
    indexed = sorted(range(n), key=lambda i: vals[i])
    return indexed  # perm[rank] = original_index

def stable_rank(vals):
    """Return rank permutation (ties broken by original index)."""
    return sorted(range(len(vals)), key=lambda i: (vals[i], i))

def vals_to_97_perm(vals):
    """
    Given a list of numerical values (any length), produce a 97-element permutation.
    Method: rank-order, map into 0..96.
    """
    n = len(vals)
    if n < 97: return None
    # Take first 97 after ranking the 107 (or however many we have)
    indexed = sorted(range(n), key=lambda i: (vals[i], i))
    # indexed[k] = position in original that has rank k
    # We want a permutation of K4[0..96], so we need to select 97 from n
    # Strategy: take the 97 hole positions with lowest rank, in their original reading order
    selected = sorted(indexed[:97])  # first 97 by rank, then sort by original position
    # Now map selected positions to K4 positions
    # The reading order of holes maps to K4 positions
    perm = selected  # hole_reading_order[selected[i]] → K4[i]? No...
    return None  # handled case by case

# ── Approach B: Distance from each hole to T-diagonal ────────────────────────
print("\n═══ APPROACH B: Hole distance to T-diagonal ═══")

def manhattan_to_T(r, c):
    return abs(c - t_col(r))

def euclidean_to_T(r, c):
    return math.sqrt((c - t_col(r))**2)  # rows are same, so just column dist

b_dists = [manhattan_to_T(r, c) for (r,c) in HOLES]
print(f"  Distance stats: min={min(b_dists)}, max={max(b_dists)}, mean={sum(b_dists)/len(b_dists):.2f}")
print(f"  Distance distribution: {sorted(Counter(b_dists).items())}")

# Check if any holes are AT T-diagonal (distance=0)
zero_dist = [(i, HOLES[i]) for i,d in enumerate(b_dists) if d == 0]
print(f"  Holes at distance 0 (ON T-diagonal): {zero_dist}")

# B1: Sort holes by distance ASC (closest to T first) → reading order permutation
for desc, key_fn in [
    ("closest_first", lambda i: (b_dists[i], i)),
    ("farthest_first", lambda i: (-b_dists[i], i)),
    ("closest_then_readorder", lambda i: (b_dists[i], HOLES[i][0]*33+HOLES[i][1])),
    ("farthest_then_readorder", lambda i: (-b_dists[i], HOLES[i][0]*33+HOLES[i][1])),
]:
    ordered = sorted(range(107), key=key_fn)
    # Select first 97, use their reading-order positions as the permutation
    # i.e., perm[k] = ordered[k] means "K4 position ordered[k] goes to CT position k"
    for select in ['first97', 'last97']:
        if select == 'first97':
            sel = ordered[:97]
        else:
            sel = ordered[10:]  # last 97 of 107
        # sel are indices into HOLES list (reading order), so they ARE 0..106 positions
        # perm: sel[i] gives the i-th "source" hole in some ordering
        # But we need a permutation of 0..96, not 0..106
        # So: among the 107 holes, select 97 of them; these 97 holes (in reading order) = CT positions
        # Then the permutation reorders them
        if select == 'first97':
            sel_sorted = sorted(sel)  # sort by reading order index
            perm = sel_sorted  # perm[i] = hole_reading_index; hole maps to K4 position
        else:
            sel_sorted = sorted(sel)
            perm = [s - 10 for s in sel_sorted]  # offset
        # For this to be a valid perm of 0..96 we need sel_sorted == [0..96] or similar
        # sel_sorted is indices 0..106, so we need to map to 0..96
        # Actually: if we select ANY 97 holes, they form a subsequence of reading order
        # The permutation of K4 is: K4[hole_reading_idx] → CT[rank_among_selected]
        # Let's do it properly:
        # We pick 97 holes. These holes, in T-distance order, define how to read K4.
        # perm[output_pos] = K4_input_pos
        perm97 = ordered[:97] if select == 'first97' else ordered[10:]
        # But these are hole indices (0..106), and K4 has 97 chars
        # So we map: K4 position = hole's sequential position
        # If hole_idx = perm97[k], then K4[hole_idx] is K4's k-th char... but K4 is indexed 0..96
        # Simple mapping: treat perm97 as permutation of 0..96 (if all values < 97)
        valid_perm = [p for p in perm97 if p < 97]
        if len(valid_perm) == 97 and len(set(valid_perm)) == 97:
            r = test_perm(valid_perm, f'B_{desc}_{select}')
            print(f"  B_{desc}_{select}: score={r[0]:.2f}" if r else f"  B_{desc}_{select}: no result")

# B2: Use distance values (0-dist) directly as permutation key for columnar transposition
for W in [7, 8, 13, 14, 26, 28, 97]:
    # Lay K4 in W columns, use T-distances of first W holes as column order
    if W > 107: continue
    key_vals = b_dists[:W]
    col_order = sorted(range(W), key=lambda c: (key_vals[c], c))
    n_rows = math.ceil(97 / W)
    perm = []
    for c in col_order:
        for r in range(n_rows):
            idx = r * W + c
            if idx < 97: perm.append(idx)
    if is_valid_perm(perm):
        r = test_perm(perm, f'B_dist_columnar_W{W}')
        print(f"  B_dist_columnar_W{W}: score={r[0]:.2f}" if r else f"  W{W}: invalid")
        # Also try inverse
        inv = invert_perm(perm)
        r = test_perm(inv, f'B_dist_columnar_inv_W{W}')
        print(f"  B_dist_columnar_inv_W{W}: score={r[0]:.2f}" if r else "")

# ── Approach C: T-relative offset per hole ────────────────────────────────────
print("\n═══ APPROACH C: T-relative offset per hole ═══")

# For each hole at (row, col): offset = (col - t_col(row)) % 26
# This is the offset of the hole FROM the T-position in its row
c_offsets = [(c - t_col(r)) % 26 for (r, c) in HOLES]
c_signed_offsets = [c - t_col(r) for (r, c) in HOLES]  # signed, range ~ -25 to +25
print(f"  Offset stats: min={min(c_offsets)}, max={max(c_offsets)}")
print(f"  Signed offset range: [{min(c_signed_offsets)}, {max(c_signed_offsets)}]")
print(f"  Offset distribution: {sorted(Counter(c_offsets).items())}")

# C1: Sort holes by T-offset → permutation
for desc, key_fn in [
    ("offset_asc", lambda i: (c_offsets[i], i)),
    ("offset_desc", lambda i: (-c_offsets[i], i)),
    ("signed_offset_asc", lambda i: (c_signed_offsets[i], i)),
    ("signed_offset_desc", lambda i: (-c_signed_offsets[i], i)),
    ("offset_asc_readorder", lambda i: (c_offsets[i], HOLES[i][0]*33+HOLES[i][1])),
    ("offset_desc_readorder", lambda i: (-c_offsets[i], HOLES[i][0]*33+HOLES[i][1])),
]:
    ordered = sorted(range(107), key=key_fn)
    first97 = ordered[:97]
    valid = [p for p in first97 if p < 97]
    if len(valid) == 97 and len(set(valid)) == 97:
        res = test_perm(valid, f'C_{desc}')
        print(f"  C_{desc}: score={res[0]:.2f}" if res else f"  C_{desc}: no result")

# C2: Use T-offsets as columnar key
for W in [7, 8, 13, 14, 26, 28]:
    key_vals = c_offsets[:W]
    col_order = sorted(range(W), key=lambda c: (key_vals[c], c))
    n_rows = math.ceil(97 / W)
    perm = []
    for c in col_order:
        for r_idx in range(n_rows):
            idx = r_idx * W + c
            if idx < 97: perm.append(idx)
    if is_valid_perm(perm):
        res = test_perm(perm, f'C_offset_columnar_W{W}')
        print(f"  C_offset_columnar_W{W}: score={res[0]:.2f}" if res else "")
        inv = invert_perm(perm)
        test_perm(inv, f'C_offset_columnar_inv_W{W}')

# C3: T-offset XOR with hole sequential index
c_xor = [c_offsets[i] ^ i for i in range(107)]
ordered_xor = sorted(range(107), key=lambda i: (c_xor[i], i))
first97_xor = [p for p in ordered_xor[:97] if p < 97]
if len(first97_xor) == 97 and len(set(first97_xor)) == 97:
    res = test_perm(first97_xor, 'C_xor_offset_hole_idx')
    print(f"  C_xor: score={res[0]:.2f}" if res else "  C_xor: no result")

# C4: T-offset as KA/AZ letter, use as running Vig key on K4 index
# Map offset→letter, use as Vigenère key
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    key97 = ''.join(alpha[c_offsets[i] % 26] for i in range(97))
    for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
        pt = fn(K4, key97, AZ)
        if pt:
            sc = qgscore(pt)
            ene = pt.find(CRIB1); bc = pt.find(CRIB2)
            if ene >= 0 or bc >= 0:
                print(f"\n*** CRIB HIT [C_offset_as_key/{alpha_name}/{cipher_name}]: ENE@{ene} BC@{bc}")
                print(f"    PT: {pt}")
            if sc > -7.5:
                print(f"  C_offset_as_key_{alpha_name}_{cipher_name}: score={sc:.2f}")

# ── Approach D: T as boundary marker (left/right region partitioning) ─────────
print("\n═══ APPROACH D: T as boundary (left/right regions) ═══")

left_holes  = [i for i,(r,c) in enumerate(HOLES) if c < t_col(r)]
right_holes = [i for i,(r,c) in enumerate(HOLES) if c > t_col(r)]
on_diag     = [i for i,(r,c) in enumerate(HOLES) if c == t_col(r)]
print(f"  Left of T: {len(left_holes)}, Right of T: {len(right_holes)}, On diagonal: {len(on_diag)}")

# D1: Left first, then right (in reading order)
for desc, order in [
    ("left_right", left_holes + right_holes),
    ("right_left", right_holes + left_holes),
    ("left_right_interleaved", [x for pair in itertools.zip_longest(left_holes, right_holes) for x in pair if x is not None]),
    ("right_left_interleaved", [x for pair in itertools.zip_longest(right_holes, left_holes) for x in pair if x is not None]),
]:
    first97 = [p for p in order if p < 97][:97]
    if len(first97) == 97 and len(set(first97)) == 97:
        res = test_perm(first97, f'D_{desc}')
        print(f"  D_{desc}: score={res[0]:.2f}" if res else f"  D_{desc}: no result")

# D2: Left holes → first half of K4, right holes → second half
# Partition K4 by T-boundary
n_left = len(left_holes)
n_right = len(right_holes)
total = n_left + n_right
print(f"  Left={n_left}, Right={n_right}, Total non-diagonal={total}")

# D3: Use T-boundary to split K4 into two halves, then recombine
for split in [48, 49, 50, 51]:
    # Assign first 'split' K4 chars to left region, rest to right
    lh_sorted = sorted(left_holes)
    rh_sorted = sorted(right_holes)
    perm = []
    l_idx = 0; r_idx = 0
    for i in range(97):
        if i < split:
            if l_idx < len(lh_sorted) and lh_sorted[l_idx] < 97:
                perm.append(lh_sorted[l_idx]); l_idx += 1
            else:
                perm.append(i)  # fallback
        else:
            if r_idx < len(rh_sorted) and rh_sorted[r_idx] < 97:
                perm.append(rh_sorted[r_idx]); r_idx += 1
            else:
                perm.append(i)
    if is_valid_perm(perm):
        res = test_perm(perm, f'D_split_{split}')
        print(f"  D_split_{split}: score={res[0]:.2f}" if res else "")

# ── Approach E: T-count as positional encoding ────────────────────────────────
print("\n═══ APPROACH E: T-count before each hole (positional encoding) ═══")

def t_count_before(row, col):
    """How many T's appear in tableau before (row,col) in reading order?"""
    # Each row has exactly one T at column t_col(r)
    # T's in rows 0..row-1: row complete rows = row T's
    # T in current row at t_col(row): add 1 if col > t_col(row)
    count = row  # T's from rows above
    if col > t_col(row):
        count += 1
    return count

e_counts = [t_count_before(r, c) for (r, c) in HOLES]
print(f"  T-count stats: min={min(e_counts)}, max={max(e_counts)}")
print(f"  T-count distribution: {sorted(Counter(e_counts).items())}")

# E1: Sort holes by T-count
for desc, key_fn in [
    ("tcount_asc", lambda i: (e_counts[i], i)),
    ("tcount_desc", lambda i: (-e_counts[i], i)),
    ("tcount_asc_readorder", lambda i: (e_counts[i], HOLES[i][0]*33+HOLES[i][1])),
]:
    ordered = sorted(range(107), key=key_fn)
    first97 = [p for p in ordered[:97] if p < 97]
    if len(first97) == 97 and len(set(first97)) == 97:
        res = test_perm(first97, f'E_{desc}')
        print(f"  E_{desc}: score={res[0]:.2f}" if res else f"  E_{desc}: no result")

# E2: T-count as columnar key
for W in [7, 8, 13, 14, 26, 28]:
    key_vals = e_counts[:W]
    col_order = sorted(range(W), key=lambda c: (key_vals[c], c))
    n_rows = math.ceil(97 / W)
    perm = []
    for c in col_order:
        for r_idx in range(n_rows):
            idx = r_idx * W + c
            if idx < 97: perm.append(idx)
    if is_valid_perm(perm):
        res = test_perm(perm, f'E_tcount_columnar_W{W}')
        print(f"  E_tcount_columnar_W{W}: score={res[0]:.2f}" if res else "")
        test_perm(invert_perm(perm), f'E_tcount_columnar_inv_W{W}')

# E3: T-count as row index in columnar transposition
# Use T-count to determine which row each K4 char belongs to
# Group K4 chars by T-count of their corresponding hole
by_tcount = defaultdict(list)
for i, tc in enumerate(e_counts[:97]):  # only first 97 holes
    by_tcount[tc].append(i)
perm_tcount = []
for tc in sorted(by_tcount.keys()):
    perm_tcount.extend(sorted(by_tcount[tc]))
if is_valid_perm(perm_tcount):
    res = test_perm(perm_tcount, 'E_tcount_group_asc')
    print(f"  E_tcount_group_asc: score={res[0]:.2f}" if res else "  E_tcount_group_asc: no result")

# ── Approach F: T-avoidance bit encoding ─────────────────────────────────────
print("\n═══ APPROACH F: T-avoidance bit encoding ═══")

# For each hole: is it "close" (dist ≤ threshold) or "far" (dist > threshold)?
for threshold in [1, 2, 3, 5, 10]:
    bits = [0 if b_dists[i] <= threshold else 1 for i in range(107)]
    n_zero = bits.count(0); n_one = bits.count(1)
    print(f"  threshold={threshold}: {n_zero} close (0), {n_one} far (1)")

    # Use bits to interleave: 0-bits give positions for one group, 1-bits for other
    zeros = [i for i,b in enumerate(bits[:97]) if b == 0]
    ones  = [i for i,b in enumerate(bits[:97]) if b == 1]

    for desc, order in [
        (f"close_first_t{threshold}", zeros + ones),
        (f"far_first_t{threshold}", ones + zeros),
    ]:
        if len(order) == 97 and len(set(order)) == 97:
            res = test_perm(order, f'F_{desc}')
            if res: print(f"  F_{desc}: score={res[0]:.2f}")

# F2: Binary string → integer → mod 97 arithmetic
for threshold in [3, 5, 8]:
    bits = [0 if b_dists[i] <= threshold else 1 for i in range(107)]
    # Interpret 97-bit prefix as binary number, reduce mod 97
    bit_str = ''.join(str(b) for b in bits[:97])
    n = int(bit_str, 2) if len(bit_str) == 97 else 0
    shift = n % 97
    perm = [(i + shift) % 97 for i in range(97)]
    if is_valid_perm(perm):
        res = test_perm(perm, f'F_bitshift_t{threshold}')
        if res and res[0] > -7.5:
            print(f"  F_bitshift_t{threshold}: shift={shift} score={res[0]:.2f}")

# F3: T-avoidance distance sign as reading direction
# For holes left of T (signed_offset < 0): read left-to-right
# For holes right of T (signed_offset > 0): read right-to-left within row
def adjusted_col(r, c):
    """Reflect column if hole is to right of T."""
    if c > t_col(r):
        return 33 - 1 - c  # mirror
    return c

adj_keys = [(HOLES[i][0] * 33 + adjusted_col(HOLES[i][0], HOLES[i][1])) for i in range(107)]
ordered_adj = sorted(range(107), key=lambda i: adj_keys[i])
first97_adj = [p for p in ordered_adj[:97] if p < 97]
if len(first97_adj) == 97 and len(set(first97_adj)) == 97:
    res = test_perm(first97_adj, 'F_reflected_cols')
    print(f"  F_reflected_cols: score={res[0]:.2f}" if res else "  F_reflected_cols: no result")

# ── Approach G: "T is your position" — key reconstruction ────────────────────
print("\n═══ APPROACH G: T is your position (key reconstruction) ═══")

T_AZ = AZ.index('T')  # = 19
T_KA = KA.index('T')  # = 4

def t_position_key(ct_str, alpha, mode='vig'):
    """
    For each CT char, find the key value that would produce PT=T.
    Vig: PT = (CT - key) mod 26 = T → key = (CT - T) mod 26
    Beau: PT = (key - CT) mod 26 = T → key = (T + CT) mod 26
    """
    T_idx = alpha.index('T')
    result = []
    for c in ct_str:
        ci = alpha.find(c)
        if ci < 0: return None
        if mode == 'vig':
            ki = (ci - T_idx) % 26
        else:  # beau
            ki = (T_idx + ci) % 26
        result.append(alpha[ki])
    return ''.join(result)

for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    for mode in ['vig', 'beau']:
        key97 = t_position_key(K4, alpha, mode)
        if not key97: continue
        print(f"\n  G_{alpha_name}_{mode} key: {key97}")

        # Use these 97 key values as:
        # G1: Columnar transposition key (use numeric values as column ordering)
        key_nums = [alpha.index(c) for c in key97]  # 97 values 0-25

        for W in [7, 8, 13, 14, 19, 26]:
            col_key = key_nums[:W]
            col_order = sorted(range(W), key=lambda c: (col_key[c], c))
            n_rows = math.ceil(97 / W)
            perm = []
            for c in col_order:
                for r_idx in range(n_rows):
                    idx = r_idx * W + c
                    if idx < 97: perm.append(idx)
            if is_valid_perm(perm):
                res = test_perm(perm, f'G_{alpha_name}_{mode}_columnar_W{W}')
                if res and res[0] > -7.5:
                    print(f"  G_{alpha_name}_{mode}_columnar_W{W}: score={res[0]:.2f}")
                test_perm(invert_perm(perm), f'G_{alpha_name}_{mode}_columnar_inv_W{W}')

        # G2: Use key as running Vig/Beau to decrypt K4 directly
        for cipher_name2, fn2 in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn2(K4, key97, AZ)
            if pt:
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT [G_direct/{alpha_name}/{mode}/{cipher_name2}]: ENE@{ene} BC@{bc}")
                    print(f"    key: {key97}")
                    print(f"    PT: {pt}")
                if sc > -7.5:
                    print(f"  G_direct_{alpha_name}_{mode}_{cipher_name2}: score={sc:.2f}")

        # G3: Key as rank permutation (stable-sort positions by key value)
        perm_g3 = stable_rank(key_nums)
        if is_valid_perm(perm_g3):
            res = test_perm(perm_g3, f'G_{alpha_name}_{mode}_rank_perm')
            if res and res[0] > -7.5:
                print(f"  G_{alpha_name}_{mode}_rank_perm: score={res[0]:.2f}")
            test_perm(invert_perm(perm_g3), f'G_{alpha_name}_{mode}_rank_perm_inv')

        # G4: Key as k-shift Caesar rotation
        shift_val = sum(key_nums) % 97
        perm_shift = [(i + shift_val) % 97 for i in range(97)]
        if is_valid_perm(perm_shift):
            res = test_perm(perm_shift, f'G_{alpha_name}_{mode}_sum_shift')
            if res and res[0] > -7.5:
                print(f"  G_{alpha_name}_{mode}_sum_shift (shift={shift_val}): score={res[0]:.2f}")

        # G5: Group positions by key value, reconstruct CT
        groups = defaultdict(list)
        for i, v in enumerate(key_nums):
            groups[v].append(i)
        perm_g5 = []
        for v in sorted(groups.keys()):
            perm_g5.extend(sorted(groups[v]))
        if is_valid_perm(perm_g5):
            res = test_perm(perm_g5, f'G_{alpha_name}_{mode}_group_asc')
            if res and res[0] > -7.5:
                print(f"  G_{alpha_name}_{mode}_group_asc: score={res[0]:.2f}")
            perm_g5_desc = []
            for v in sorted(groups.keys(), reverse=True):
                perm_g5_desc.extend(sorted(groups[v]))
            if is_valid_perm(perm_g5_desc):
                test_perm(perm_g5_desc, f'G_{alpha_name}_{mode}_group_desc')

# ── Novel H: T-diagonal as fold axis ─────────────────────────────────────────
print("\n═══ APPROACH H: T-diagonal as fold axis ═══")

# The T-diagonal zigzags through the tableau.
# Idea: for each K4 position i, "fold" it about the T-column of its corresponding hole.
# The folded position = 2 * t_col(row) - col (mirror about T-column)
folded_keys = []
for i, (r, c) in enumerate(HOLES[:97]):
    tc = t_col(r)
    folded = (2 * tc - c) % 33  # reflect column about T-column
    folded_keys.append(folded * 28 + r)  # row-major in transposed grid

# Sort by folded key → permutation
perm_fold = sorted(range(97), key=lambda i: (folded_keys[i], i))
res = test_perm(perm_fold, 'H_fold_reflect')
print(f"  H_fold_reflect: score={res[0]:.2f}" if res else "  H_fold_reflect: no result")

# H2: Also try fold with modular distance
fold_dists = [abs(c - 2*t_col(r) + c) % 26 for (r, c) in HOLES[:97]]
perm_fold2 = sorted(range(97), key=lambda i: (fold_dists[i], i))
test_perm(perm_fold2, 'H_fold_dist')

# ── Novel I: T-column sum hash → rotation ────────────────────────────────────
print("\n═══ APPROACH I: T-column arithmetic rotations ═══")

# Sum of T-column values for rows that contain holes
rows_with_holes = list({r for r, c in HOLES})
t_col_sum = sum(t_col(r) for r in rows_with_holes) % 97
print(f"  T-col sum for rows-with-holes mod 97: {t_col_sum}")

for shift in [t_col_sum, (97 - t_col_sum) % 97, T_AZ, T_KA, 4, 19]:
    perm = [(i + shift) % 97 for i in range(97)]
    res = test_perm(perm, f'I_rotation_{shift}')
    if res and res[0] > -7.5:
        print(f"  I_rotation_{shift}: score={res[0]:.2f}")

# Also: use T-column as period for block reversal
for period in T_COLS[:10]:
    if period == 0: continue
    perm = []
    for block_start in range(0, 97, period):
        block = list(range(block_start, min(block_start + period, 97)))
        perm.extend(reversed(block))
    if is_valid_perm(perm):
        res = test_perm(perm, f'I_block_rev_period{period}')
        if res and res[0] > -7.5:
            print(f"  I_block_rev_period{period}: score={res[0]:.2f}")

# ── Novel J: T-column in KA as Vigenère key for unscrambling ─────────────────
print("\n═══ APPROACH J: T-column position sequence as Vig/Beau key ═══")

# The T-column positions for rows 0-27: [4,3,2,1,0,25,24,...,5,4,3]
# Convert to letters in AZ/KA and use as periodic Vig/Beau key

for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    # 28-char key from T-column positions (first 26 are unique, last 2 repeat)
    key28 = ''.join(alpha[t_col(r)] for r in range(28))
    key26 = ''.join(alpha[t_col(r)] for r in range(26))  # unique cycle
    for key, klen in [(key28, 28), (key26, 26)]:
        for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, key, AZ)
            if pt:
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT [J/{alpha_name}/{klen}/{cipher_name}]: ENE@{ene} BC@{bc}")
                    print(f"    key: {key}")
                    print(f"    PT: {pt}")
                if sc > -7.5:
                    print(f"  J_{alpha_name}_key{klen}_{cipher_name}: score={sc:.2f}")

# ── Novel K: Hole coordinates as base-33/28 number → permutation ─────────────
print("\n═══ APPROACH K: Hole coordinates as numbers ═══")

# For each hole i at (row, col): compute a number n_i = row * 33 + col (reading order)
# These 107 numbers, mod 97, give values 0-96 (with possible duplicates/missing)
hole_nums_33 = [r * 33 + c for (r, c) in HOLES]
hole_nums_26 = [r * 26 + c for (r, c) in HOLES]  # if alphabet-width is 26

for name, nums in [("base33", hole_nums_33), ("base26", hole_nums_26)]:
    mods = [n % 97 for n in nums]
    print(f"  {name} mod 97 - unique values: {len(set(mods))}, range: [{min(mods)},{max(mods)}]")

    # K1: Sort holes by mod value → permutation
    ordered = sorted(range(107), key=lambda i: (mods[i], i))
    first97 = [p for p in ordered[:97] if p < 97]
    if len(first97) == 97 and len(set(first97)) == 97:
        res = test_perm(first97, f'K_{name}_mod97_sort')
        if res: print(f"  K_{name}_mod97_sort: score={res[0]:.2f}")

    # K2: Use first 97 hole numbers directly as permutation indices
    direct97 = [n % 97 for n in nums[:97]]
    if len(set(direct97)) == 97:  # only if all unique
        res = test_perm(direct97, f'K_{name}_direct97')
        if res and res[0] > -7.5:
            print(f"  K_{name}_direct97: score={res[0]:.2f}")

# ── Novel L: T-position in KA letter → KA-index arithmetic ──────────────────
print("\n═══ APPROACH L: KA-letter T-position arithmetic ═══")

# The grille extract gives 106 KA letters. Their KA-indices tell us something.
# "T is your position" → T_KA = 4. What if we use 4 in arithmetic on each letter?
extract_ka_indices = [KA.index(c) for c in GRILLE_EXTRACT]  # 106 values 0-25
extract97_ka = extract_ka_indices[:97]
extract97_shifted = [(v + T_KA) % 26 for v in extract97_ka]  # add T's KA index
extract97_shifted_neg = [(v - T_KA) % 26 for v in extract97_ka]  # subtract

for name, vals in [
    ("ka_idx", extract97_ka),
    ("ka_idx_plus_T", extract97_shifted),
    ("ka_idx_minus_T", extract97_shifted_neg),
    ("ka_idx_plus_T_AZ", [(v + T_AZ) % 26 for v in extract97_ka]),
]:
    # L1: Use as columnar key
    for W in [7, 8, 13, 14, 26]:
        col_key = vals[:W]
        col_order = sorted(range(W), key=lambda c: (col_key[c], c))
        n_rows = math.ceil(97 / W)
        perm = []
        for c in col_order:
            for r_idx in range(n_rows):
                idx = r_idx * W + c
                if idx < 97: perm.append(idx)
        if is_valid_perm(perm):
            res = test_perm(perm, f'L_{name}_columnar_W{W}')
            if res and res[0] > -7.5:
                print(f"  L_{name}_columnar_W{W}: score={res[0]:.2f}")

    # L2: Rank permutation of the 97 values
    perm_rank = stable_rank(vals)
    if is_valid_perm(perm_rank):
        res = test_perm(perm_rank, f'L_{name}_rank')
        if res and res[0] > -7.5:
            print(f"  L_{name}_rank: score={res[0]:.2f}")
        test_perm(invert_perm(perm_rank), f'L_{name}_rank_inv')

# ── Novel M: T-column per row × hole_col_in_row → combined key ───────────────
print("\n═══ APPROACH M: T-column product/quotient encoding ═══")

# For hole at (r, c): product = (t_col(r) * c) % 97
m_product = [(t_col(r) * c) % 97 for (r, c) in HOLES[:97]]
m_sum     = [(t_col(r) + c) % 97 for (r, c) in HOLES[:97]]
m_diff    = [(t_col(r) - c) % 97 for (r, c) in HOLES[:97]]
m_xor     = [(t_col(r) ^ c)     for (r, c) in HOLES[:97]]

for name, vals in [("product", m_product), ("sum", m_sum), ("diff", m_diff), ("xor", m_xor)]:
    perm_r = stable_rank(vals)
    if is_valid_perm(perm_r):
        res = test_perm(perm_r, f'M_{name}_rank')
        if res and res[0] > -7.5:
            print(f"  M_{name}_rank: score={res[0]:.2f}")
    # Columnar
    for W in [7, 13, 26, 28]:
        col_key = vals[:W]
        col_order = sorted(range(W), key=lambda c: (col_key[c] % 26, c))
        n_rows = math.ceil(97 / W)
        perm = []
        for c in col_order:
            for r_idx in range(n_rows):
                idx = r_idx * W + c
                if idx < 97: perm.append(idx)
        if is_valid_perm(perm):
            res = test_perm(perm, f'M_{name}_columnar_W{W}')
            if res and res[0] > -7.5:
                print(f"  M_{name}_columnar_W{W}: score={res[0]:.2f}")

# ── Novel N: Row-by-row T-column based strip reading ─────────────────────────
print("\n═══ APPROACH N: Row-by-row T-anchored strip reading ═══")

# Sort holes WITHIN each row by distance to T, then concatenate rows
# This gives a reordering of the 107 holes where within each row, chars
# nearest T come first (or last)
row_groups = defaultdict(list)
for i, (r, c) in enumerate(HOLES):
    row_groups[r].append((i, c, b_dists[i]))

strip_perms = {}
for row_sort_desc, within_row_key in [
    ("nearest_T_first", lambda x: (x[2], x[1])),
    ("farthest_T_first", lambda x: (-x[2], x[1])),
    ("right_of_T_first", lambda x: (-c_signed_offsets[x[0]], x[1])),
    ("left_of_T_first", lambda x: (c_signed_offsets[x[0]], x[1])),
]:
    ordered_indices = []
    for r in sorted(row_groups.keys()):
        row_holes = sorted(row_groups[r], key=within_row_key)
        ordered_indices.extend([h[0] for h in row_holes])

    first97 = [p for p in ordered_indices[:97] if p < 97]
    if len(first97) == 97 and len(set(first97)) == 97:
        res = test_perm(first97, f'N_{row_sort_desc}')
        print(f"  N_{row_sort_desc}: score={res[0]:.2f}" if res else f"  N_{row_sort_desc}: no result")

    # Also try from last 97
    last97 = [p for p in ordered_indices[10:] if p < 97]
    if len(last97) >= 97:
        last97 = last97[:97]
        if len(set(last97)) == 97:
            res = test_perm(last97, f'N_{row_sort_desc}_last97')
            if res and res[0] > -7.5:
                print(f"  N_{row_sort_desc}_last97: score={res[0]:.2f}")

# ── Novel O: "T is your position" — T-column directly indexes K4 ─────────────
print("\n═══ APPROACH O: T-column directly indexes K4 positions ═══")

# For row r with T at t_col(r): the REAL CT position r is K4[t_col(r)]?
# Or: real CT[r] = K4[T_col_for_row_r]
# If rows map to K4 positions directly:
for n_rows_try in [28, 26, 25, 24, 20]:
    t_perm = [t_col(r) for r in range(n_rows_try)]
    # This gives only 26 unique values (period 26), not a 97-permutation directly
    # Use T-column values as indices into K4 for the "key" rows
    key_from_t = ''.join(K4[t_col(r) % 97] for r in range(n_rows_try))
    for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
        pt = fn(K4, key_from_t, AZ)
        if pt:
            sc = qgscore(pt)
            ene = pt.find(CRIB1); bc = pt.find(CRIB2)
            if ene >= 0 or bc >= 0:
                print(f"\n*** CRIB HIT [O/rows{n_rows_try}/{cipher_name}]: ENE@{ene} BC@{bc}")
                print(f"    key: {key_from_t}")
                print(f"    PT: {pt}")
            if sc > -7.5:
                print(f"  O_rows{n_rows_try}_{cipher_name}: score={sc:.2f}")

# O2: T-column positions of holes as mapping
# hole[i] is at (r_i, c_i). T-col of row r_i is t_col(r_i).
# What if: the REAL CT position is t_col(r_i), not i?
# Build mapping from t_col(r) → K4[i] for all holes
for select97 in ['first97', 'all107']:
    holes_sel = HOLES[:97] if select97 == 'first97' else HOLES
    mapping = {}
    for i, (r, c) in enumerate(holes_sel):
        tc = t_col(r)
        k4_idx = i if i < 97 else None
        if k4_idx is not None:
            mapping[tc] = k4_idx  # last-write wins

    if len(mapping) >= 97:
        perm_o2 = [mapping.get(v, v) for v in range(97)]
        if is_valid_perm(perm_o2):
            res = test_perm(perm_o2, f'O2_{select97}_tcol_as_dest')
            if res and res[0] > -7.5:
                print(f"  O2_{select97}: score={res[0]:.2f}")

# ── Novel P: Grille extract as Beaufort alphabet for each K4 char ─────────────
print("\n═══ APPROACH P: Extract as position-dependent Beaufort alphabet ═══")

# Each of 106 extract chars is a KA letter. What if extract[i] is the
# "row key" for K4[i], and we use the T-column of that row to get a shift?
# I.e., decode K4[i] using row determined by extract[i]'s position in KA
for sel_start in [0, 9]:  # try first 97 or last 97 of extract
    extract97 = GRILLE_EXTRACT[sel_start:sel_start+97]
    if len(extract97) != 97: continue

    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        # For each K4[i], use extract[i] to determine the "row" in KA tableau
        # Row r determined by: alpha.index(extract[i])
        # T-col in that row: t_col(r)
        # Shift: t_col(r)
        # Decrypt K4[i] with this shift
        shifts = [t_col(alpha.find(extract97[i]) % 26) for i in range(97)]

        # As Vig with variable shift
        pt_vig = ''.join(AZ[(AZ.index(K4[i]) - shifts[i]) % 26] for i in range(97))
        sc = qgscore(pt_vig)
        ene = pt_vig.find(CRIB1); bc = pt_vig.find(CRIB2)
        if ene >= 0 or bc >= 0:
            print(f"\n*** CRIB HIT [P_extract_tcol_vig/{alpha_name}/{sel_start}]: ENE@{ene} BC@{bc}")
            print(f"    PT: {pt_vig}")
        if sc > -7.5:
            print(f"  P_extract_tcol_vig_{alpha_name}_s{sel_start}: score={sc:.2f}")

        pt_beau = ''.join(AZ[(shifts[i] - AZ.index(K4[i])) % 26] for i in range(97))
        sc = qgscore(pt_beau)
        ene = pt_beau.find(CRIB1); bc = pt_beau.find(CRIB2)
        if ene >= 0 or bc >= 0:
            print(f"\n*** CRIB HIT [P_extract_tcol_beau/{alpha_name}/{sel_start}]: ENE@{ene} BC@{bc}")
            print(f"    PT: {pt_beau}")
        if sc > -7.5:
            print(f"  P_extract_tcol_beau_{alpha_name}_s{sel_start}: score={sc:.2f}")

# ── Novel Q: KA-index of extract chars mod 97 as direct permutation ───────────
print("\n═══ APPROACH Q: KA-index of extract chars as direct permutation ═══")

# If the 106 extract chars encode a 97-permutation:
# Method 1: extract_ka_indices[i] * scaling mod 97
for scale in [1, 2, 3, 4, 7, 13, 14, 26]:
    vals97 = [(extract_ka_indices[i] * scale) % 97 for i in range(97)]
    if len(set(vals97)) == 97:
        res = test_perm(vals97, f'Q_scale{scale}')
        if res and res[0] > -7.5:
            print(f"  Q_scale{scale}: score={res[0]:.2f}")

# Method 2: pair consecutive extract chars to get values 0-96
# extract[2i]*26 + extract[2i+1] → but this needs 194 chars total → skip

# Method 3: extract char KA-index + T_KA * position, mod 97
for mult in [1, 2, 3, 4, T_KA, T_AZ]:
    vals97 = [(extract_ka_indices[i] + mult * i) % 97 for i in range(97)]
    if len(set(vals97)) == 97:
        res = test_perm(vals97, f'Q_linear_{mult}')
        if res and res[0] > -7.5:
            print(f"  Q_linear_{mult}: score={res[0]:.2f}")

# ── Novel R: Two-pass — use T-distance to split, then sub-permute each half ──
print("\n═══ APPROACH R: Two-pass split and sub-permute ═══")

# Split 107 holes into near-T (dist ≤ 5) and far-T (dist > 5)
near_idx = [i for i in range(107) if b_dists[i] <= 5]
far_idx  = [i for i in range(107) if b_dists[i] > 5]
print(f"  Near-T (dist≤5): {len(near_idx)}, Far-T (dist>5): {len(far_idx)}")

# Try reading K4 in this order
combined = near_idx + far_idx
first97 = [p for p in combined[:97] if p < 97]
if len(first97) == 97 and len(set(first97)) == 97:
    res = test_perm(first97, 'R_near_then_far')
    print(f"  R_near_then_far: score={res[0]:.2f}" if res else "  R_near_then_far: no result")

combined_rev = far_idx + near_idx
first97_rev = [p for p in combined_rev[:97] if p < 97]
if len(first97_rev) == 97 and len(set(first97_rev)) == 97:
    res = test_perm(first97_rev, 'R_far_then_near')
    print(f"  R_far_then_near: score={res[0]:.2f}" if res else "")

# ── Novel S: T-diagonal as route cipher guide ─────────────────────────────────
print("\n═══ APPROACH S: T-diagonal as route cipher guide ═══")

# The T-column zigzags: 4,3,2,1,0,25,24,...,5 (decreasing then wrapping)
# This looks like a DIAGONAL through a grid.
# What if K4 is laid in a 26×? grid and read following this diagonal?

for W in [25, 26, 27]:
    n_rows = math.ceil(97 / W)
    # T-diagonal visits (r, (4-r)%26) for r = 0, 1, 2, ...
    # Read K4 along the T-diagonal first, then read remaining chars
    diagonal_positions = []
    off_diagonal_positions = []
    for r in range(n_rows):
        tc = t_col(r) % W
        for c in range(W):
            pos = r * W + c
            if pos >= 97: break
            if c == tc:
                diagonal_positions.append(pos)
            else:
                off_diagonal_positions.append(pos)

    perm_diag_first = diagonal_positions + off_diagonal_positions
    if is_valid_perm(perm_diag_first, 97):
        res = test_perm(perm_diag_first, f'S_diag_first_W{W}')
        if res and res[0] > -7.5:
            print(f"  S_diag_first_W{W}: score={res[0]:.2f}")

    perm_off_first = off_diagonal_positions + diagonal_positions
    if is_valid_perm(perm_off_first, 97):
        res = test_perm(perm_off_first, f'S_off_diag_first_W{W}')
        if res and res[0] > -7.5:
            print(f"  S_off_diag_first_W{W}: score={res[0]:.2f}")

# ── Novel T: Combine T-distance + T-offset as 2D sort key ────────────────────
print("\n═══ APPROACH T: 2D sort by (T-offset, T-distance) ═══")

# Sort holes by (T-offset, T-distance, reading-order) — 2D sorting
for desc, key_fn in [
    ("offset_then_dist", lambda i: (c_offsets[i], b_dists[i], i)),
    ("dist_then_offset", lambda i: (b_dists[i], c_offsets[i], i)),
    ("offset_then_dist_desc", lambda i: (c_offsets[i], -b_dists[i], i)),
    ("signed_then_dist", lambda i: (c_signed_offsets[i], b_dists[i], i)),
    ("dist_then_signed", lambda i: (b_dists[i], c_signed_offsets[i], i)),
    ("tcount_then_offset", lambda i: (e_counts[i], c_offsets[i], i)),
    ("tcount_then_dist", lambda i: (e_counts[i], b_dists[i], i)),
]:
    ordered = sorted(range(107), key=key_fn)
    first97 = [p for p in ordered[:97] if p < 97]
    if len(first97) == 97 and len(set(first97)) == 97:
        res = test_perm(first97, f'T_{desc}')
        if res and res[0] > -7.5:
            print(f"  T_{desc}: score={res[0]:.2f}")

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n═══ SUMMARY ═══")
if RESULTS:
    RESULTS.sort(key=lambda x: -x[0])
    print(f"\nTop results (score > -7.5):")
    seen = set()
    for r in RESULTS[:30]:
        sc, name, perm, pt, kw, cipher, alpha = r
        key = f"{name}_{kw}_{cipher}_{alpha}"
        if key in seen: continue
        seen.add(key)
        ene = pt.find(CRIB1); bc = pt.find(CRIB2)
        crib_str = f"ENE@{ene}" if ene>=0 else ""
        crib_str += f" BC@{bc}" if bc>=0 else ""
        print(f"  {sc:.2f} [{name}] key={kw} {cipher}/{alpha} {crib_str}")
        print(f"       PT: {pt[:60]}...")

    # Save results
    with open(f'{OUT_DIR}/results.json', 'w') as f:
        json.dump([{"score": r[0], "name": r[1], "perm": r[2], "pt": r[3],
                    "key": r[4], "cipher": r[5], "alpha": r[6]} for r in RESULTS[:30]], f, indent=2)
    print(f"\nSaved top results to {OUT_DIR}/results.json")
else:
    print("No results above threshold.")

print("\nDone! All approaches exhausted.")
