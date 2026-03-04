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
blitz_t_targeted.py — Targeted novel T-position approaches.

Key new angles:
1. T-hole K4 chars (B,F,S,A at positions 12,21,33,90) as keywords
2. T-hole coordinates as VIC-style indicators for block keys
3. Option-C tableau formula (letter=(c-r)%26) — only 2 T-hits, different permutations
4. "8 Lines 73" with keyed columnar on segments
5. Reverse composition with best known permutations
6. Brute force short-key Vig on random permutations seeded by T-structure
7. Direct GRILLE_EXTRACT as running key (various selections and directions)
"""

import sys, json, os, math, itertools, random
from collections import defaultdict, Counter

sys.path.insert(0, 'src')

K4  = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA  = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
CRIB1 = "EASTNORTHEAST"
CRIB2 = "BERLINCLOCK"

# Expanded keywords including T-hole derived ones
# K4 chars at T-hole positions [12,21,33,90]:
# K4[12]=B, K4[21]=F, K4[33]=S, K4[90]=A → "BFSA"
KEYWORDS_BASE = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
                 'BERLIN','CLOCK','BERLINCLOCK','EAST','NORTH','NORTHEAST','LIGHT',
                 'ANTIPODES','MEDUSA','ENIGMA','LAYER','ILLUSION','IQLUSION']
KEYWORDS_THOLES = ['BFSA','ASFB','BSFA','FSAB','SFAB','FABS',  # permutations of BFSA
                   'BFS','BSA','FSA','FAB','SAB','BFSAZ',
                   'KBFSA','BFSAKR']
KEYWORDS_EXTRA  = ['COMPASS','PYRAMID','LANGLEY','VIRGINIA','AGENCY',
                   'CARTER','EGYPT','TOMB','TUTANKHAMUN','HIEROGLYPH']
KEYWORDS = list(dict.fromkeys(KEYWORDS_BASE + KEYWORDS_THOLES + KEYWORDS_EXTRA))

OUT_DIR = 'blitz_results/t_position'
os.makedirs(OUT_DIR, exist_ok=True)

qg = json.load(open('data/english_quadgrams.json'))
def qgscore(text):
    return sum(qg.get(text[i:i+4].upper(), -10.0) for i in range(len(text)-3))

SCORE_THRESHOLD = -600
RESULTS = []
tested = set()

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

def test_perm(perm, name):
    if not is_valid_perm(perm): return None
    pk = tuple(perm)
    if pk in tested: return None
    tested.add(pk)
    candidate_ct = apply_perm(K4, perm)
    best = (-9999, None)
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
                    print(f"    key={kw} {cipher_name}/{alpha_name}")
                    print(f"    CT: {candidate_ct}")
                    print(f"    PT: {pt}")
                    print(f"    Score: {sc:.2f}")
                    print(f"{'='*70}\n")
                    RESULTS.append({'name':name,'score':sc,'perm':list(perm),'pt':pt,'key':kw,'cipher':cipher_name,'alpha':alpha_name,'ct':candidate_ct})
                if sc > best[0]:
                    best = (sc, pt)
    if best[0] > SCORE_THRESHOLD:
        RESULTS.append({'name':name,'score':best[0],'pt':best[1],'perm':list(perm)})
    return best

def test_key_directly(key, name):
    """Test key as direct Vig/Beau on K4 (no permutation step)."""
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, key, alpha)
            if pt is None: continue
            sc = qgscore(pt)
            ene = pt.find(CRIB1); bc = pt.find(CRIB2)
            if ene >= 0 or bc >= 0:
                print(f"\n*** CRIB HIT [{name}/{cipher_name}/{alpha_name}]: ENE@{ene} BC@{bc}")
                print(f"    key: {key[:30]}...")
                print(f"    PT: {pt}")
            if sc > SCORE_THRESHOLD:
                print(f"  {name}_{cipher_name}_{alpha_name}: score={sc:.2f}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: T-hole K4 chars as keywords / key seeds
# ══════════════════════════════════════════════════════════════════════════════
print("═══ SECTION 1: T-hole K4 chars as keywords ═══")

t4_positions = [12, 21, 33, 90]
t4_k4_chars = [K4[i] for i in t4_positions]
print(f"K4 chars at T-holes {t4_positions}: {''.join(t4_k4_chars)} = {t4_k4_chars}")

# Try all 24 orderings of BFSA as keyword
bfsa_perms = list(itertools.permutations(t4_k4_chars))
for bp in bfsa_perms:
    kw = ''.join(bp)
    test_key_directly(kw, f'bfsa_perm_{kw}')

# Also with surrounding chars (sliding window around T-holes)
for t_idx in t4_positions:
    for window in range(3, 9):
        start = max(0, t_idx - window//2)
        end   = min(97, start + window)
        kw = K4[start:end]
        test_key_directly(kw, f'window_{t_idx}_W{window}')

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: All GRILLE_EXTRACT selections as direct keys
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 2: GRILLE_EXTRACT selections as direct Vig keys ═══")

# Forward and reverse, all 97-char windows of the 106-char extract
for start in range(10):
    for direction in [1, -1]:
        if direction == 1:
            key = GRILLE_EXTRACT[start:start+97]
        else:
            key = GRILLE_EXTRACT[start:start+97][::-1]
        if len(key) != 97: continue
        test_key_directly(key, f'extract_s{start}_d{direction}')

# Also GRILLE_EXTRACT as permutation directly using KA-index
for start in range(10):
    ge_slice = GRILLE_EXTRACT[start:start+97]
    if len(ge_slice) != 97: continue
    vals = [KA.index(c) for c in ge_slice]
    perm = stable_rank(vals)
    if is_valid_perm(perm):
        test_perm(perm, f'extract_rank_s{start}')
        test_perm(invert_perm(perm), f'extract_rank_inv_s{start}')

# Reversed extract as permutation
for start in range(10):
    ge_slice = GRILLE_EXTRACT[start:start+97][::-1]
    if len(ge_slice) != 97: continue
    vals = [KA.index(c) for c in ge_slice]
    perm = stable_rank(vals)
    if is_valid_perm(perm):
        test_perm(perm, f'extract_rank_rev_s{start}')

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: Option-C tableau formula (c-r)%26
# T-hits at (17,21) and (22,26) under this formula
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 3: Option-C tableau formula letter=(c-r)%26 ═══")

# Under option C: letter at (r,c) = KA[(c-r)%26]
letters_optC = [KA[(c-r)%26] for r,c in HOLES[:97]]
t_count_C = letters_optC.count('T')
print(f"Option-C: {t_count_C} T's in first 97 holes' letters")

# Use option-C letters as running key
key_optC = ''.join(letters_optC)
test_key_directly(key_optC, 'optC_key_97')

# Use option-C letter ranks as permutation
vals_C = [KA.index(c) for c in letters_optC]
perm_C = stable_rank(vals_C)
if is_valid_perm(perm_C):
    test_perm(perm_C, 'optC_rank_perm')
    test_perm(invert_perm(perm_C), 'optC_rank_perm_inv')

# T-offset in option-C: letter is KA[(c-r)%26], T is KA[4]
# Offset = (c-r-4+26)%26
toff_C = [(c - r - 4 + 52) % 26 for r,c in HOLES[:97]]
perm_toffC = stable_rank(toff_C)
if is_valid_perm(perm_toffC):
    test_perm(perm_toffC, 'optC_toff_rank')

# Also try full 107 holes with option C
letters_optC_107 = [KA[(c-r)%26] for r,c in HOLES]
t_pos_C = [i for i,l in enumerate(letters_optC_107) if l == 'T']
print(f"Option-C: T at hole positions {t_pos_C}")

# Non-T holes as permutation
non_t_C = [i for i in range(107) if letters_optC_107[i] != 'T']
first97_C = [p for p in non_t_C[:97] if p < 97]
if len(first97_C) == 97 and len(set(first97_C)) == 97:
    test_perm(first97_C, 'optC_nonT_perm')

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: Segment permutations with EXPANDED keyword list
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 4: 5-segment perms with all keywords ═══")

segs_t4 = [
    list(range(0, 12)),    # seg 0: 12 chars
    list(range(12, 21)),   # seg 1: 9 chars
    list(range(21, 33)),   # seg 2: 12 chars
    list(range(33, 90)),   # seg 3: 57 chars
    list(range(90, 97)),   # seg 4: 7 chars
]

best_seg_score = -9999
best_seg_name = None

count_seg = 0
for seg_perm in itertools.permutations(range(5)):
    for do_reverse in [False, True]:  # try original and reversed
        perm = []
        for si in seg_perm:
            seg = segs_t4[si][:]
            if do_reverse:
                seg = list(reversed(seg))
            perm.extend(seg)
        if not is_valid_perm(perm): continue
        res = test_perm(perm, f'seg_{"".join(str(s) for s in seg_perm)}_rev{int(do_reverse)}')
        count_seg += 1
        if res and res[0] > best_seg_score:
            best_seg_score = res[0]
            best_seg_name = f'seg_{"".join(str(s) for s in seg_perm)}_rev{int(do_reverse)}'

print(f"  Tested {count_seg} segment permutations")
print(f"  Best segment score: {best_seg_score:.2f} [{best_seg_name}]")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: Grille extract as permutation with different selection methods
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 5: Extract→permutation via various methods ═══")

# Method: use extract chars as a running columnar key
for W in range(2, 31):
    col_key = [KA.index(GRILLE_EXTRACT[i]) for i in range(W)]
    col_order = sorted(range(W), key=lambda c: (col_key[c], c))
    n_rows = math.ceil(97/W)
    perm = []
    for c in col_order:
        for r_idx in range(n_rows):
            idx = r_idx * W + c
            if idx < 97: perm.append(idx)
    if is_valid_perm(perm):
        res = test_perm(perm, f'extract_col_W{W}')
        if res and res[0] > best_seg_score:
            best_seg_score = res[0]
        # also inverse
        inv = invert_perm(perm)
        test_perm(inv, f'extract_col_inv_W{W}')

print(f"  Ran extract columnar for W=2..30")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6: T-hole coordinates arithmetic → permutation
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 6: T-hole coordinate arithmetic → permutation ═══")

t_hole_coords = [HOLES[i] for i in t4_positions]
print(f"T-hole coordinates: {t_hole_coords}")

# Try each T-hole coordinate as a key value
for (r, c) in t_hole_coords:
    for val in [r, c, r+c, r*c%26, (r*c)%97, abs(r-c), max(r,c), min(r,c)]:
        # Use val as a rotation
        perm = [(i + val) % 97 for i in range(97)]
        test_perm(perm, f'coord_{r}_{c}_rot_{val}')
        # As columnar key of width val
        if 2 <= val <= 30:
            col_key = [val] * val
            # Use coordinate values as col ordering key
            for W in [val, val+1, val-1]:
                if W < 2 or W > 30: continue
                col_key_w = [HOLES[i][0] + HOLES[i][1] for i in range(W)]
                col_order = sorted(range(W), key=lambda cc: (col_key_w[cc]%W, cc))
                n_rows = math.ceil(97/W)
                perm2 = []
                for cc in col_order:
                    for ri in range(n_rows):
                        idx = ri*W + cc
                        if idx < 97: perm2.append(idx)
                if is_valid_perm(perm2):
                    test_perm(perm2, f'coord_col_val{val}_W{W}')

# T-hole rows and cols as separate keys
t_rows = [r for r,c in t_hole_coords]  # [3, 7, 12, 23]
t_cols = [c for r,c in t_hole_coords]  # [27, 23, 18, 7]
print(f"T-hole rows: {t_rows}, cols: {t_cols}")

# Product: 3*7=21, 7*12=84, 12*23=276%97=82, 23*3=69
# Sum: 3+7=10, 7+12=19, 12+23=35, 23+3=26
for vals, name in [(t_rows, 'rows'), (t_cols, 'cols'),
                   ([r+c for r,c in t_hole_coords], 'sum'),
                   ([(r*c)%26 for r,c in t_hole_coords], 'prod26')]:
    for val in vals:
        perm = [(i + val) % 97 for i in range(97)]
        test_perm(perm, f'tholecoord_{name}_rot{val}')

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7: "T is your position" — most literal reading
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 7: 'T is your position' literal readings ═══")

# Reading 1: Position of T in AZ alphabet = 19 (0-indexed), 20 (1-indexed)
# Position of T in KA alphabet = 4 (0-indexed), 5 (1-indexed)
# "T is your position" → start reading K4 at position T in KA = position 4
# → Rotation by 4 (T's KA index)

for start_pos in [4, 5, 19, 20, 4*4, 4+4, 4*5, 19+4, 19*4%97, 20*4%97,
                  97-4, 97-19, 97-5, 97-20]:
    perm = [(i + start_pos) % 97 for i in range(97)]
    test_perm(perm, f'literal_T_rot_{start_pos}')

# Reading 2: "T is your position" → position 4 in KA = position index for KA-Vig
# Use KA Vig with a key derived from T's position
T_KA = 4
key_from_T = AZ[T_KA]  # = 'E'
test_key_directly(key_from_T * 97, f'T_as_single_key_{key_from_T}')
key_from_T_KA = KA[T_KA]  # = 'T'
test_key_directly(key_from_T_KA * 97, f'T_as_single_key_T')

# Reading 3: "position" → index. T at different places:
# AZ index 19, KA index 4. "YOUR position" → user's? K4 index?
# The CRIBS are at positions 21-33 (ENE) and 63-73 (BC). T at position 20 (T)?
# K4[20] = W. Hmm.
# Under KA indexing for K4: K4[4]=U (T's KA position)
# K4[19]=B (T's AZ position)
print(f"K4[4]={K4[4]} (T's KA-idx), K4[19]={K4[19]} (T's AZ-idx)")

# Reading 4: "T" → look in K4 where T appears
t_positions_k4 = [i for i,c in enumerate(K4) if c == 'T']
print(f"T appears in K4 at positions: {t_positions_k4}")

# Use T-positions in K4 as segment dividers (like T-holes, but in K4 itself)
prev = 0
segs_k4T = []
for tp in t_positions_k4:
    segs_k4T.append(list(range(prev, tp)))
    prev = tp + 1
segs_k4T.append(list(range(prev, 97)))
segs_k4T = [s for s in segs_k4T if s]  # remove empty

print(f"K4 T-segments: {[len(s) for s in segs_k4T]} = {sum(len(s) for s in segs_k4T)} non-T chars")
print(f"Total: {sum(len(s) for s in segs_k4T)} non-T + {len(t_positions_k4)} T = {sum(len(s) for s in segs_k4T)+len(t_positions_k4)}")

# Reading 5: T in K4 as SKIP markers → read K4 non-T chars in order
non_t_k4 = [i for i in range(97) if K4[i] != 'T']
print(f"Non-T K4 positions: {len(non_t_k4)}")

# If we remove T's and use non-T chars as the "real CT" prefix:
# This gives 91 non-T chars. To get 97, we'd need to add back T's at specific positions.

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8: T-distance-based multi-round permutations
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 8: Multi-round T-distance permutations ═══")

# Initial T-distances with k=0 formula
t_dists_init = [abs(c - (4-r)%26) for r,c in HOLES[:97]]

# Apply permutation multiple times (power of a permutation)
perm_base = stable_rank(t_dists_init)
if is_valid_perm(perm_base):
    perm_power = list(range(97))
    for power in range(1, 10):
        # Apply perm_base to perm_power
        perm_power = [perm_power[perm_base[i]] for i in range(97)]
        test_perm(perm_power, f'tdist_perm_power_{power}')

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9: Stochastic search seeded by T-structure
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 9: Stochastic search seeded by T-structure ═══")

# Start from T-distance rank permutation and apply local swaps to improve score
# This is a simple hill-climber to check if any nearby permutation is better

random.seed(42)

def hill_climb(start_perm, max_iters=10000, name="HC"):
    """Simple hill-climbing on permutation space."""
    perm = list(start_perm)
    candidate_ct = apply_perm(K4, perm)
    # Find best score over all keywords
    best_sc = -9999
    best_pt = None
    best_kw = None
    best_cipher = None
    best_alpha = None
    for kw in ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','BERLIN','CLOCK','BFSA']:
        for fn, fname in [(vig_dec,'vig'), (beau_dec,'beau')]:
            pt = fn(candidate_ct, kw, AZ)
            if pt:
                sc = qgscore(pt)
                if sc > best_sc:
                    best_sc = sc; best_pt = pt; best_kw = kw; best_cipher = fname; best_alpha = 'AZ'

    for iteration in range(max_iters):
        # Try a random swap
        i, j = random.sample(range(97), 2)
        perm[i], perm[j] = perm[j], perm[i]
        ct_new = apply_perm(K4, perm)
        sc_new = -9999
        for kw in ['KRYPTOS','PALIMPSEST','ABSCISSA']:
            pt = vig_dec(ct_new, kw, AZ)
            if pt: sc_new = max(sc_new, qgscore(pt))
        if sc_new >= best_sc:  # accept equal or better
            best_sc = sc_new
        else:
            perm[i], perm[j] = perm[j], perm[i]  # revert

    # Check final result with all keywords
    candidate_ct = apply_perm(K4, perm)
    for kw in KEYWORDS:
        for fn, fname in [(vig_dec,'vig'), (beau_dec,'beau')]:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                pt = fn(candidate_ct, kw, alpha)
                if pt:
                    sc = qgscore(pt)
                    ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                    if ene >= 0 or bc >= 0:
                        print(f"\n*** CRIB HIT [HC/{name}/{kw}/{fname}/{alpha_name}]: ENE@{ene} BC@{bc}")
                        print(f"    PT: {pt}")
    return best_sc, perm

# Run hill-climbers from different starts
starts = [
    (stable_rank(t_dists_init), 'tdist_rank'),
    (stable_rank([KA.index(c) for c in GRILLE_EXTRACT[:97]]), 'extract_rank'),
    (list(range(97)), 'identity'),
    (list(reversed(range(97))), 'reverse'),
]

for start, sname in starts:
    if is_valid_perm(start):
        sc, final_perm = hill_climb(start, max_iters=5000, name=sname)
        print(f"  HC from {sname}: final score={sc:.2f}")
        test_perm(final_perm, f'HC_{sname}_final')

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10: Grille holes as K4 substring extractors
# ══════════════════════════════════════════════════════════════════════════════
print("\n═══ SECTION 10: Grille holes as K4 substring extractors ═══")

# What if: the grille is placed over K4 directly (not the tableau)?
# K4 is laid in a 28×33 or compatible grid, and the grille holes select chars.

# For K4 in a 28×4 = 112-char grid (K4 fills first 97, rest empty):
# hole at (r,c): K4_pos = r*4 + c (if c<4 and r*4+c < 97)
for grid_cols in [4, 7, 13, 14]:
    k4_positions_from_holes = []
    for r, c in HOLES:
        pos = r * grid_cols + c
        if 0 <= pos < 97 and c < grid_cols:
            k4_positions_from_holes.append(pos)

    # Unique valid positions
    seen = set()
    uniq = []
    for p in k4_positions_from_holes:
        if p not in seen:
            seen.add(p)
            uniq.append(p)

    print(f"  Grid {28}×{grid_cols}: {len(uniq)} unique K4 positions from holes")

    if len(uniq) >= 97 and len(set(uniq[:97])) == 97:
        res = test_perm(uniq[:97], f'hole_grid_{28}x{grid_cols}')
        if res and res[0] > SCORE_THRESHOLD:
            print(f"  hole_grid_{28}x{grid_cols}: {res[0]:.2f}")

# Also try K4 in column-major order on the grid
for grid_cols in [4, 7, 13, 14]:
    k4_pos_col_major = []
    for r, c in HOLES:
        pos = c * 28 + r  # column-major
        if 0 <= pos < 97:
            k4_pos_col_major.append(pos)

    seen = set()
    uniq = []
    for p in k4_pos_col_major:
        if p not in seen:
            seen.add(p)
            uniq.append(p)

    if len(uniq) >= 97 and len(set(uniq[:97])) == 97:
        res = test_perm(uniq[:97], f'hole_colmaj_grid_{grid_cols}')
        if res and res[0] > SCORE_THRESHOLD:
            print(f"  hole_colmaj_grid_{grid_cols}: {res[0]:.2f}")

# ── Final Summary ─────────────────────────────────────────────────────────────
print(f"\n═══ FINAL SUMMARY ═══")
print(f"Total unique permutations tested: {len(tested)}")
if RESULTS:
    RESULTS.sort(key=lambda x: -x['score'])
    print(f"\nTop results (score > {SCORE_THRESHOLD}):")
    seen_names = set()
    for r in RESULTS[:20]:
        key = r['name']
        if key in seen_names: continue
        seen_names.add(key)
        pt = r.get('pt','')
        crib_str = f"ENE@{pt.find(CRIB1)}" if pt.find(CRIB1)>=0 else ""
        crib_str += f" BC@{pt.find(CRIB2)}" if pt.find(CRIB2)>=0 else ""
        print(f"  {r['score']:.2f} [{r['name']}] {crib_str}")
        print(f"       PT: {pt[:60]}...")

    with open(f'{OUT_DIR}/targeted_results.json', 'w') as f:
        json.dump(RESULTS[:20], f, indent=2, default=str)
    print(f"\nSaved to {OUT_DIR}/targeted_results.json")
else:
    print("No results above threshold.")

print("\nDone!")
