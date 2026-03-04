"""
Cipher: Cardan grille
Family: grille
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_k3_grille_v3.py — Targeted K4 permutation search.

KEY FINDINGS FROM V1/V2:
- K3 is PURE TRANSPOSITION (confirmed, no Vigenère)
- K3 reading order uses steps -145/+192 in K3-1D space
- Continuation doesn't reach K4 territory
- No hits from single/double rotation grids 97-110, shape reading orders

THIS SCRIPT:
1. Grille extract as keyword columnar permutation (sort-based, width 97)
2. Test additional crib "YESWONDERFULTHINGS" at K4 PT position 0
3. Large double-rotation search (grids up to size 200) for K4
4. K4 structural analysis: 4+31+31+31 shape, transpositions based on seam
5. The 97-prime transposition via stripe/offset reading of 14×31 grid

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_k3_grille_v3.py
"""
from __future__ import annotations
import sys, math
from collections import Counter

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ["KRYPTOS","PALIMPSEST","ABSCISSA","SHADOW","SANBORN",
            "SCHEIDT","BERLIN","CLOCK","EAST","NORTH",
            "LIGHT","ANTIPODES","MEDUSA","ENIGMA"]

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4_CARVED) == 97

ENE = "EASTNORTHEAST"   # PT[21:34]
BC  = "BERLINCLOCK"     # PT[63:74]
YWT = "YESW"           # PT likely starts with YES + something

# From blitz campaign: expected real_CT at crib positions under Vig/KRYPTOS/AZ
# real_CT[21:34] = "ORQIGCJDYCPLH"
# real_CT[63:74] = "LVPABBUVFAZ"
EXPECTED_REALCT_ENE_KRYPTOS_AZ = "ORQIGCJDYCPLH"
EXPECTED_REALCT_BC_KRYPTOS_AZ  = "LVPABBUVFAZ"

# ─── Cipher ───────────────────────────────────────────────────────────────────
def vig_decrypt(ct, key, alpha=AZ):
    res = []
    for i, c in enumerate(ct):
        ci = alpha.index(c); ki = alpha.index(key[i%len(key)])
        res.append(alpha[(ci-ki)%26])
    return "".join(res)

def vig_encrypt(pt, key, alpha=AZ):
    res = []
    for i, c in enumerate(pt):
        pi = alpha.index(c); ki = alpha.index(key[i%len(key)])
        res.append(alpha[(pi+ki)%26])
    return "".join(res)

def beau_decrypt(ct, key, alpha=AZ):
    res = []
    for i, c in enumerate(ct):
        ci = alpha.index(c); ki = alpha.index(key[i%len(key)])
        res.append(alpha[(ki-ci)%26])
    return "".join(res)

def check_cribs(pt):
    ene_ok = len(pt) > 33 and pt[21:34] == ENE
    bc_ok  = len(pt) > 73 and pt[63:74] == BC
    ene_any = ENE in pt
    bc_any  = BC in pt
    return ene_ok, bc_ok, ene_any, bc_any

def test_all_ciphers(real_ct, tag=""):
    """Test real_ct against all keywords/ciphers. Return True on crib hit."""
    for kw in KEYWORDS:
        for aname, alpha in [("AZ",AZ),("KA",KA)]:
            for cname, cfn in [("vig",vig_decrypt),("beau",beau_decrypt)]:
                try:
                    pt = cfn(real_ct, kw, alpha)
                    ene_ok, bc_ok, ene_any, bc_any = check_cribs(pt)
                    if ene_ok or bc_ok or ene_any or bc_any:
                        print(f"  *** CRIB HIT [{tag}] {cname}/{kw}/{aname} ***")
                        print(f"      ENE@21={ene_ok}, BC@63={bc_ok}, anywhere={ene_any or bc_any}")
                        print(f"      PT: {pt}")
                        return True
                except (ValueError, IndexError):
                    pass
    return False

def test_perm_full(sigma, tag=""):
    """Test sigma (pure + all ciphers). sigma[j] = carved position for real_CT[j]."""
    assert len(sigma) == 97 and len(set(sigma)) == 97
    real_ct = "".join(K4_CARVED[sigma[j]] for j in range(97))
    # Pure transposition first
    pt_pure = real_ct
    ene_ok, bc_ok, ene_any, bc_any = check_cribs(pt_pure)
    if ene_ok or bc_ok or ene_any or bc_any:
        print(f"  *** PURE TRANSPOSITION HIT [{tag}] ***")
        print(f"      PT: {pt_pure}")
        return True
    return test_all_ciphers(real_ct, tag)

def count_crib_chars(pt):
    """Count how many crib characters match at expected positions."""
    ene_count = sum(1 for i in range(13) if len(pt)>21+i and pt[21+i]==ENE[i])
    bc_count  = sum(1 for i in range(11) if len(pt)>63+i and pt[63+i]==BC[i])
    return ene_count, bc_count

# ─── 1. GRILLE EXTRACT AS KEYWORD PERMUTATION ────────────────────────────────
print("="*70)
print("1. GRILLE EXTRACT AS KEYWORD PERMUTATION (width 97)")
print("="*70)

# Corrected grille extract (100 chars from corrected 28×31 grid)
GRILLE_EXTRACT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"
GRILLE_OLD     = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

for name, extract in [("corrected_100", GRILLE_EXTRACT), ("old_106", GRILLE_OLD)]:
    for length in [97, 100, 106]:
        key = extract[:min(length, len(extract))]
        if len(key) < 97: continue

        # Use only first 97 chars of key for a width-97 keyword transposition
        key97 = key[:97]
        # sigma[j] = original position of j-th char in alphabetical order
        # This gives a permutation of {0..96}
        pairs = sorted(range(97), key=lambda i: (key97[i], i))
        sigma_kw = pairs  # already indices in 0..96
        if len(set(sigma_kw)) != 97:
            continue

        tag = f"grille_{name}_len{length}_kw_col"
        hit = test_perm_full(sigma_kw, tag)

        # Method 2: reverse keyword order
        sigma_kw_rev = list(reversed(sigma_kw))
        hit2 = test_perm_full(sigma_kw_rev, tag+"_rev")

    # Method 3: use AZ indices of extract chars mod 97, deduplicated
    # Not a valid perm in general due to repeats — skip

# Method 4: use KA indices
for name, extract in [("corrected", GRILLE_EXTRACT), ("old", GRILLE_OLD)]:
    key97 = extract[:97] if len(extract) >= 97 else None
    if key97 is None: continue
    pairs_ka = sorted(range(97), key=lambda i: (KA.index(key97[i]) if key97[i] in KA else 99, i))
    if len(set(pairs_ka)) == 97:
        test_perm_full(pairs_ka, f"grille_{name}_KA_col")
        test_perm_full(list(reversed(pairs_ka)), f"grille_{name}_KA_col_rev")

print("  (grille extract as keyword: done)")

# ─── 2. ADDITIONAL CRIBS AND PARTIAL-CRIB SCORING ───────────────────────────
print("\n" + "="*70)
print("2. TESTING WITH ADDITIONAL CRIBS (YES at pos 0, WONDERFUL at some pos)")
print("="*70)

# K4 PT likely starts "YESW" (answer to K3's "CANYOUSEEANYTHING?")
# Check any permutation that gives YESW at position 0..3
# This narrows down: σ(0) must be a position of Y in K4_carved
Y_positions = [i for i, c in enumerate(K4_CARVED) if c == 'Y']
E_positions = [i for i, c in enumerate(K4_CARVED) if c == 'E']
S_positions = [i for i, c in enumerate(K4_CARVED) if c == 'S']
W_positions = [i for i, c in enumerate(K4_CARVED) if c == 'W']

print(f"Y positions in K4_carved: {Y_positions}")
print(f"E positions in K4_carved: {E_positions}")
print(f"S positions in K4_carved: {S_positions}")
print(f"W positions in K4_carved: {W_positions}")
print(f"YWT='YESW' requires σ(0)={Y_positions}, σ(1)={E_positions}, σ(2)={S_positions}, σ(3)={W_positions}")

# For pure transposition with YWT crib: check all permutations (too many)
# Instead, check: for each candidate that satisfies main cribs, also check YWT

# ─── 3. LARGE DOUBLE-ROTATION SEARCH ────────────────────────────────────────
print("\n" + "="*70)
print("3. LARGE DOUBLE-ROTATION SEARCH (N up to 200 for K4)")
print("="*70)

def double_rotation_perm(N, w1, h1, w2=None, h2=None, rot1='cw', rot2='cw'):
    """Get permutation of first 97 positions under double rotation.
    Write 0..N-1 in w1×h1 grid, rotate, write in w2×h2 grid, rotate, read out.
    Returns sigma where sigma[j] = source position for output position j,
    considering only the first 97 output positions, only if they form a perm of 0..96."""
    if w2 is None:
        w2 = h1; h2 = w1  # Natural second grid for double rotation
    assert w1*h1 == w2*h2 == N

    # First rotation: write 0..N-1 in w1×h1 (width=w1, height=h1)
    def rot90cw(grid_flat, width, height):
        """Rotate 90°CW: input width×height → output height×width."""
        out = [0]*(width*height)
        for r in range(height):
            for c in range(width):
                # new position: new_r = c, new_c = height-1-r, new_width = height
                new_r = c; new_c = height-1-r
                out[new_r*height + new_c] = grid_flat[r*width + c]
        return out

    step1 = rot90cw(list(range(N)), w1, h1)  # result has width=h1, height=w1
    step2 = rot90cw(step1, h1, w1)           # result has width=w1, height=h1... wait
    # After first rotation: new width = h1, new height = w1
    # After second rotation on this: new width = w1, new height = h1
    # Hmm, this gives back original orientation but permuted.
    # Actually we want to write step1 into w2×h2, then rotate.
    # For standard double rotation: w2=h1, h2=N//h1.

    # Re-do with explicit w2,h2:
    step2 = rot90cw(step1, w2, h2)  # step1 arranged as w2×h2, then rotated
    # step2 has width=h2, height=w2

    # step2[j] = original index that ends up at position j
    if len(step2) != N: return None
    # Only take first 97 positions of step2
    result = step2[:97]
    if len(set(result)) != 97: return None
    if set(result) != set(range(97)): return None
    return result

# Test all (N, w1, h1) where N ∈ [97..200] and w1*h1 = N
hits = 0
tested = 0
near_hits = []

for N in range(97, 201):
    for w1 in range(2, N):
        if N % w1 != 0: continue
        h1 = N // w1
        # Try multiple second-grid configurations
        for w2 in range(2, N):
            if N % w2 != 0: continue
            h2 = N // w2
            if w2 == w1: continue  # skip same as first

            tested += 1
            result = double_rotation_perm(N, w1, h1, w2, h2)
            if result is None: continue

            pt_pure = "".join(K4_CARVED[result[j]] for j in range(97))
            ene_ok, bc_ok, ene_any, bc_any = check_cribs(pt_pure)
            if ene_ok or bc_ok or ene_any or bc_any:
                print(f"  *** PURE HIT: N={N}, w1={w1},h1={h1},w2={w2},h2={h2} ***")
                print(f"      PT: {pt_pure}")
                hits += 1

            # Quick crib count for near-hits
            ene_c, bc_c = count_crib_chars(pt_pure)
            if ene_c >= 8 or bc_c >= 6:
                near_hits.append((N, w1, h1, w2, h2, ene_c, bc_c, pt_pure[:40]))
            # Also test with cipher
            if not (ene_ok or bc_ok or ene_any or bc_any):
                real_ct = pt_pure  # IS the pure candidate
                for kw in ["KRYPTOS"]:  # just KRYPTOS for speed
                    for alpha in [AZ, KA]:
                        for cfn in [vig_decrypt, beau_decrypt]:
                            try:
                                pt2 = cfn(real_ct, kw, alpha)
                                ene_ok2, bc_ok2, _, _ = check_cribs(pt2)
                                if ene_ok2 or bc_ok2:
                                    print(f"  *** CIPHER HIT: N={N},{w1}×{h1}→{w2}×{h2} kw={kw} ***")
                                    print(f"      PT: {pt2}")
                                    hits += 1
                            except: pass

    if N % 20 == 0:
        print(f"  Tested N≤{N}, {tested} configs so far, {hits} hits, {len(near_hits)} near-hits")

print(f"\n  Total: {tested} configs, {hits} hits")
if near_hits:
    print(f"  Near-hits (sorted by ENE count):")
    for nh in sorted(near_hits, key=lambda x: -(x[5]+x[6]))[:10]:
        print(f"    N={nh[0]}, {nh[1]}×{nh[2]}→{nh[3]}×{nh[4]}: ENE={nh[5]}/13, BC={nh[6]}/11: {nh[7]}")

# ─── 4. K4 STRUCTURAL TRANSPOSITIONS (4 + 31 + 31 + 31 = 97) ────────────────
print("\n" + "="*70)
print("4. K4 STRUCTURAL TRANSPOSITIONS: 4+31+31+31 SHAPE")
print("="*70)

# K4 has a unique shape: 4 chars then 3 full rows of 31.
# Try transpositions that exploit this "seam".

# Model: the 4-char "head" and 93-char "body" are transposed separately or together.

# Approach A: columnar transposition of entire 97 chars with width 4
# (matches the 4-char head width)
# Width 4: 97 = 24×4 + 1 = 24 rows + 1 partial
for width in [4, 7, 8, 13, 14, 31]:
    h = math.ceil(97/width)
    N = width * h
    padding = N - 97

    # Fill grid
    indices = list(range(97)) + [None]*padding
    # Read by columns (columnar transposition)
    cols = []
    for c in range(width):
        col = [indices[r*width + c] for r in range(h) if indices[r*width+c] is not None]
        cols.extend(col)
    sigma_col = cols[:97]
    if len(set(sigma_col)) == 97:
        pt = "".join(K4_CARVED[sigma_col[j]] for j in range(97))
        ene_c, bc_c = count_crib_chars(pt)
        ene_ok, bc_ok, _, _ = check_cribs(pt)
        if ene_ok or bc_ok or ene_c >= 8 or bc_c >= 6:
            print(f"  Near-hit columnar w={width}: ENE={ene_c}/13, BC={bc_c}/11")
        if ene_ok or bc_ok:
            print(f"  *** COLUMNAR HIT w={width}! ***  PT: {pt}")

        # Reverse
        sigma_rev = list(reversed(sigma_col))
        pt2 = "".join(K4_CARVED[sigma_rev[j]] for j in range(97))
        ene_c2, bc_c2 = count_crib_chars(pt2)
        if ene_c2 >= 8 or bc_c2 >= 6:
            print(f"  Near-hit columnar_rev w={width}: ENE={ene_c2}/13, BC={bc_c2}/11")

# Approach B: treat K4 as a 31×3+4 block
# 31-wide columnar on the 3 full rows, then handle the 4-char head separately
# Head (4 chars) + body (93 chars) transposed independently
def k4_head_body_trans(perm_head, perm_body):
    """Head: perm of 0..3, Body: perm of 0..92 → sigma for full K4."""
    sigma = [perm_head[i] for i in range(4)] + [4 + perm_body[i] for i in range(93)]
    return sigma

# Simple: reverse head, sort body by columns
from itertools import permutations as perms

# Too slow to try all 4! × 93! but can try structured perms of body
# Body is 93 chars = 3 rows of 31
body_perms = {}
# Row-by-row (identity)
body_perms["identity"] = list(range(93))
# Columns of 3 (column-major)
body_perms["col_major"] = [c*3+r for r in range(3) for c in range(31)]
body_perms["col_major_alt"] = [r+c*3 for c in range(31) for r in range(3)]
# Reverse
body_perms["rev"] = list(range(92, -1, -1))
# Row 1, 3, 2 order
body_perms["row_132"] = list(range(31)) + list(range(62,93)) + list(range(31,62))
# Boustrophedon
boustro_body = []
for r in range(3):
    row = list(range(r*31, (r+1)*31))
    if r%2==1: row=list(reversed(row))
    boustro_body.extend(row)
body_perms["boustro"] = boustro_body

head_perms = {}
head_perms["identity"] = [0,1,2,3]
head_perms["reverse"] = [3,2,1,0]
head_perms["rotate1"] = [1,2,3,0]
head_perms["rotate2"] = [2,3,0,1]
head_perms["rotate3"] = [3,0,1,2]

for hname, hp in head_perms.items():
    for bname, bp in body_perms.items():
        sigma = k4_head_body_trans(hp, bp)
        if len(set(sigma)) != 97: continue
        pt = "".join(K4_CARVED[sigma[j]] for j in range(97))
        ene_ok, bc_ok, ene_any, bc_any = check_cribs(pt)
        if ene_ok or bc_ok or ene_any or bc_any:
            print(f"  *** HIT head={hname} body={bname} ***  PT: {pt}")
            test_all_ciphers("".join(K4_CARVED[sigma[j]] for j in range(97)), f"head+body")

print("  (K4 structural done)")

# ─── 5. K3-DERIVED K4 PERMUTATION VIA HOLE_ORDER EXTENSION ──────────────────
print("\n" + "="*70)
print("5. K3 DOUBLE-ROTATION ON THE FULL 14×31 BOTTOM GRID (434 positions)")
print("="*70)

# HYPOTHESIS: The ENTIRE bottom half (rows 14-27, 14×31 = 434 positions)
# is processed by a SINGLE double-rotation transposition.
# K3 = positions 0..335 of the 434-char bottom half (in raster order)
# K4 = positions 337..433 (position 336 = the ? = null pad)
# Wait: K3 uses rows 14-24 cols 0-25 (336 chars) and K4 uses rows 24 cols 27-30
# + rows 25-27 (97 chars). The ? at row 24 col 26 is a separator.

# If the 434-char bottom half is processed by a double rotation:
# The first 336 chars → K3 (verify against known K3 perm)
# The remaining 97 chars → K4 permutation

# Build 434-position sequence of K3+?+K4
# Map bottom-half raster position to K3/K4 position:
def bottom_half_to_sequence():
    """Build the 434-position sequence for the bottom half."""
    seq = []
    for r in range(14, 28):
        for c in range(31):
            seq.append((r, c))
    assert len(seq) == 434
    return seq

bottom_seq = bottom_half_to_sequence()  # 434 (r,c) pairs

# Map back to K3 or K4 indices
k3_positions = set()
for r in range(14, 24):
    for c in range(31):
        k3_positions.add((r,c))
for c in range(26):
    k3_positions.add((24,c))

k4_positions = set()
for c in range(27, 31):
    k4_positions.add((24,c))
for r in range(25, 28):
    for c in range(31):
        k4_positions.add((r,c))

# The ? position: (24, 26)

# Apply K3 double-rotation formula to 434-position sequence:
# For a 434-position sequence, treat it as processed by a 14×31 → 31×14 rotation.
# Formula for 14×31 → 31×14 (90° CW):
# Input: 14 rows × 31 cols. Output: 31 rows × 14 cols.
# out[r][c] = in[14-1-c][r] = in[13-c][r]
# out_pos = r*14 + c, in_pos = (13-c)*31 + r = 13*31+r - 31*c + r
# Wait: out[new_r][new_c] = in[old_r][old_c]
# For 90° CW: new_r = old_c, new_c = height-1-old_r
# height = 14 (rows in input), width = 31 (cols in input)
# new_r = old_c, new_c = 13 - old_r
# new dimensions: 31 rows × 14 cols
# out[old_c][13-old_r] = in[old_r][old_c]
# new_pos = new_r * new_width + new_c = old_c * 14 + (13 - old_r)

def single_rot_434():
    """Single 90°CW rotation of 14×31 → 31×14, return perm of 434 positions."""
    perm = [0]*434
    for r in range(14):
        for c in range(31):
            old_pos = r*31 + c
            new_pos = c*14 + (13-r)
            perm[new_pos] = old_pos
    return perm

rot434_single = single_rot_434()
assert len(set(rot434_single)) == 434

# Apply to bottom half: what does K3 look like under this single rotation?
# K3 occupies positions in bottom_seq. We need to map:
# bottom_seq[i] = (r,c), K3 raster position j = ?

# Build K3 raster: row-major through K3 positions in order
def build_k3_raster():
    k3_raster = []
    for r in range(14, 24):
        for c in range(31):
            k3_raster.append((r,c))
    for c in range(26):
        k3_raster.append((24,c))
    return k3_raster

k3_raster = build_k3_raster()  # 336 positions

# Map (r,c) to bottom-half raster index
bottom_to_idx = {(r,c): i for i,(r,c) in enumerate(bottom_seq)}

# Under single_rot_434: bottom[rot434_single[i]] gets placed at position i
# The carved text at position i comes from source position rot434_single[i]
# For K3: the first 336 raster positions are K3. The first 336 output positions of the
# 434-rotation are some mix of K3 and K4 positions.

# Check: does the single rotation of 434 positions, restricted to K3 raster,
# match the K3 transposition we already know?

# K3 raster positions in bottom-half index space: [bottom_to_idx[(r,c)] for (r,c) in k3_raster]
k3_bottom_indices = [bottom_to_idx[(r,c)] for (r,c) in k3_raster]
# (should be 0..335 for rows 14-23 + 310..335 for row 24 cols 0-25)
# Actually these ARE 0..335 in order since K3 raster = first 336 of bottom_seq.

# Under single_rot_434:
# Source at bottom-half position rot434_single[i] ends up at position i in output.
# K3 raster positions (indices 0..335) in the OUTPUT:
# What input indices map to outputs 0..335?
# perm[output_pos] = input_pos. So output[i] = input[perm[i]].

# The carved K3 text = bottom_seq[0..335].
# Under single_rot_434: CARVED[i] (for i=0..433) = source[rot434_single[i]].
# Where source[j] is the real_CT (or PT for pure transposition).

# For K3 raster positions (carved positions 0..335 in the 434-space):
k3_perm_from_434_single = rot434_single[:336]  # indices into bottom-half of real_CT
print("Single 434 rotation: K3 perm (first 10):", k3_perm_from_434_single[:10])

# Extract K3 content from carved bottom half
# Bottom-half carved chars:
def get_bottom_chars():
    """Get all letters from bottom half rows 14-27 in raster order."""
    chars = []
    CIPHER_ROWS_RAW = [
        "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",
        "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",
        "DVFPJUDEEHZWETZYVGWHKKQETGFQJNCE",
        "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",
        "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",
        "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",
        "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",
        "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER",
        "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",
        "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",
        "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",
        "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",
        "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",
        "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",
        "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",
        "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",
        "TPRNGATIHNRARPESLNNELEBLPIIACAE",
        "WMTWNDITEENRAHCTENEUDRETNHAEOET",
        "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",
        "EIFTBRSPAMHHEWENATAMATEGYEERLBT",
        "EEFOASFIOTUETUAEOTOARMAEERTNRTI",
        "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
        "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",
        "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",
        "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",
        "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
        "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",
        "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",
    ]
    def pad_row(r):
        s = CIPHER_ROWS_RAW[r]
        if len(s)>31: s=s[:31]
        elif len(s)<31: s+='?'*(31-len(s))
        return list(s)
    grid = [pad_row(r) for r in range(28)]
    for r in range(14, 28):
        for c in range(31):
            chars.append(grid[r][c])
    return chars, grid

bottom_chars, grid_all = get_bottom_chars()
assert len(bottom_chars) == 434

# Under single_rot_434: carved[i] = source[perm[i]]
# → source[j] = carved[inv_perm[j]]
inv_rot434 = [0]*434
for i, j in enumerate(rot434_single): inv_rot434[j] = i

# Recover K3 "real CT" from the 434 rotation
# K3 occupies bottom positions 0..335 (K3 raster) and uses bottom chars 0..335
# real_CT_full[j] = bottom_chars[inv_rot434[j]]
k3_real_from_434 = "".join(bottom_chars[inv_rot434[j]] for j in range(336))
# Only take letter chars (skip ?)
k3_real_letters = "".join(c for c in k3_real_from_434 if c.isalpha())

print(f"K3 'real CT' from 434 single rotation (first 64): {k3_real_from_434[:64]}")
print(f"(letters only, first 64): {k3_real_letters[:64]}")

# Compare to known K3 PT
K3_PT_EXPECTED = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWER"
match_434 = sum(1 for i in range(min(64,len(k3_real_from_434))) if k3_real_from_434[i]==K3_PT_EXPECTED[i])
print(f"Matches with K3 PT (first 64): {match_434}/64")

if match_434 > 30:
    print("PROMISING: 434 single rotation recovers K3 PT!")
    # Extract K4 permutation from the same rotation
    # K4 occupies bottom positions 337..433
    k4_bottom_positions = [bottom_to_idx[(r,c)] for r,c in [(24,c) for c in range(27,31)]]
    k4_bottom_positions += [bottom_to_idx[(r,c)] for r in range(25,28) for c in range(31)]
    print(f"K4 bottom positions count: {len(k4_bottom_positions)}")

    # Under 434 rotation: carved K4 position maps to source positions
    k4_perm_from_434 = [inv_rot434[j] - 337 for j in range(337, 434)
                        if bottom_chars[inv_rot434[j]] != '?']
    print(f"K4 perm from 434: {k4_perm_from_434[:10]}")

# ─── 6. DOUBLE 434 ROTATION ──────────────────────────────────────────────────
print("\n" + "="*70)
print("6. DOUBLE ROTATION ON 434-POSITION BOTTOM HALF")
print("="*70)

# Try all double rotations of the 434-position bottom half
# Look for ones where the K3 portion matches known K3 transposition

def double_rot_434(w1, h1, w2, h2, chars434):
    """Apply double rotation to 434 chars."""
    if w1*h1 != 434 or w2*h2 != 434: return None

    def rot90cw_flat(flat, width, height):
        out = [None]*(width*height)
        for r in range(height):
            for c in range(width):
                new_r = c; new_c = height-1-r
                out[new_r*height + new_c] = flat[r*width+c]
        return out

    step1 = rot90cw_flat(list(chars434), w1, h1)  # width becomes h1, height becomes w1
    step2 = rot90cw_flat(step1, w2, h2)  # second rotation
    return step2

# 434 = 2 × 7 × 31 = 14 × 31 = 2 × 217 = etc.
factors_434 = [(w,434//w) for w in range(1,435) if 434%w==0]
print(f"434 factorizations: {factors_434}")

# Test double rotation on 434 bottom chars
hits_434 = 0
best_k3_match = 0

# Use bottom chars
bottom_letters = [c if c.isalpha() else '_' for c in bottom_chars]

for w1, h1 in factors_434:
    if w1 == 1 or h1 == 1: continue
    for w2, h2 in factors_434:
        if w2 == 1 or h2 == 1: continue
        if (w2, h2) == (w1, h1): continue

        result = double_rot_434(w1, h1, w2, h2, bottom_letters)
        if result is None: continue

        # Check K3 portion (first 336 output positions)
        # Under this rotation: output[i] = input[perm[i]]
        # We need the INVERSE: input[j] = output[perm^{-1}[j]]
        # result[i] = input position = bottom_letter at that position

        # Actually result[i] is the character (letter or '_')
        k3_recovered = "".join(c for c in result[:336] if c.isalpha())

        # How many chars match K3 PT?
        k3_match = sum(1 for i in range(min(len(k3_recovered), len(K3_PT_EXPECTED)))
                       if k3_recovered[i] == K3_PT_EXPECTED[i])

        if k3_match > best_k3_match:
            best_k3_match = k3_match
            print(f"  Best K3 match so far: {k3_match}/70 with {w1}×{h1}→{w2}×{h2}")
            print(f"    Recovered[:64]: {k3_recovered[:64]}")

        if k3_match >= 30:
            print(f"  NEAR-MATCH: {w1}×{h1}→{w2}×{h2}: K3={k3_match}/70")
            # Try to extract K4 perm
            k4_portion = "".join(c for c in result[336:] if c.isalpha())
            if len(k4_portion) >= 97:
                k4_letters = k4_portion[:97]
                # Check if K4 portion gives cribs
                ene_ok, bc_ok, ene_any, bc_any = check_cribs(k4_letters)
                if ene_ok or bc_ok:
                    print(f"    *** K4 CRIB HIT! PT: {k4_letters} ***")
                hits_434 += 1

print(f"\nBest K3 match from 434 double rotation: {best_k3_match}/70")

# ─── 7. VERIFY K3 PERM UNDER DIFFERENT ROTATION INTERPRETATION ───────────────
print("\n" + "="*70)
print("7. WHICH 434 ROTATION EXACTLY REPRODUCES K3 PERM?")
print("="*70)

# We know K3 perm exactly. Let's find the rotation that matches it.
# K3 perm: k3_fwd[i] = pt_pos for carved pos i (0..335)
def k3_carved_to_pt(i):
    a = i//24; b = i%24
    inter = 14*b + 13 - a
    c = inter//8; d = inter%8
    return 42*d + 41 - c

# Build K3 perm in bottom-half index space
# carved[i] = K3 CT at position i (in K3 raster = bottom raster positions 0..335)
# real_CT[j] = K3 PT at position j (in K3 raster)
# k3_carved_to_pt(i) maps carved index i → PT index j

# In the 434-position bottom half, the K3 carved positions are 0..335.
# Under a 434-rotation: rot434[i] = j means carved[i] = source[j].
# We need rot434[i] = k3_carved_to_pt(i) for i in 0..335.

# What rotation gives this?
# For i=0: need rot434[0] = k3_carved_to_pt(0) = 250 (as computed earlier)
# For i=1: need rot434[1] = k3_carved_to_pt(1) = 164
# This defines the first 336 values of the rotation permutation.
# The remaining 98 values (indices 336..433) complete the permutation.
# If the full 434-rotation is a valid rotation (consistent with some double-rotation
# formula), then the last 98 values are determined by the first 336.

# Check if the K3 perm can be extended to a 434-position rotation
k3_fwd_full = [k3_carved_to_pt(i) for i in range(336)]
# These are the VALUES of the permutation at indices 0..335.
# Values range 0..335 (all K3 positions).
# For a valid 434-rotation, values at indices 0..433 form a permutation of 0..433.
# The values 0..335 must appear at indices 0..335 (K3 positions).
# The values 336..433 must appear at indices 336..433 (K4+? positions).
# This would mean K4 uses positions 336..433 of the 434-perm.

# Check: are k3_fwd_full[0..335] = {0..335}?
k3_values_set = set(k3_fwd_full)
print(f"K3 perm values range: {min(k3_values_set)}-{max(k3_values_set)}, unique: {len(k3_values_set)}")
print(f"All K3 perm values in 0..335: {k3_values_set == set(range(336))}")

# YES! K3 perm maps {0..335} → {0..335}. So the K4 portion of the 434-perm
# maps {336..433} → {336..433} (independently).
# BUT: K4 has 97 positions (indices 337..433, since 336 is the ? position).
# So the K4 sub-permutation maps {337..433} → {337..433} (97 positions).

# This means K3 and K4 use INDEPENDENT sub-permutations of the 434-rotation!
print("\nK3 and K4 are independent sub-permutations of the 434-space.")
print("K3: indices 0..335 → values 0..335 (confirmed)")
print("K4: indices 337..433 → values 337..433 (INDEPENDENT)")

# So the K4 permutation is completely independent of K3.
# We need to find WHICH permutation of the 97 K4 positions is used.
# The constraint: it must be consistent with some 434-rotation formula.

# Try: the 434-rotation is defined by some formula (like K3's formula but for 434).
# K3's formula: a=i//24, b=i%24, inter=14*b+13-a, c=inter//8, d=inter%8, pt=42*d+41-c
# For 434 = 14×31 grid:
# Try formula with w1=31, h1=14 (natural K3-section dims):
# a = i//31, b = i%31, inter = 14*b + (14-1) - a, ...?

# The K3 formula uses widths 24 and 8. Let me try the analogous 434 formula:
# 434 = w1×h1 = w2×h2
# K3: 24×14 = 8×42 = 336. For 434: 14×31 = 31×14 = 2×7×31
# Try: w1=31, h1=14 → w2=14, h2=31 (swap)
def formula_434(i, w1=31, h1=14, w2=14, h2=31):
    """Apply K3-style double rotation formula to 434 positions."""
    a = i // w1; b = i % w1
    inter = h1 * b + (h1-1) - a
    if inter < 0 or inter >= w1*h1: return -1
    c = inter // w2; d = inter % w2
    pt = h2 * d + (h2-1) - c
    return pt

# Test formula on K3 positions (0..335)
matches_formula = sum(1 for i in range(336)
                     if formula_434(i) == k3_carved_to_pt(i))
print(f"\n434 formula (31×14→14×31) matches K3 formula: {matches_formula}/336")

# Try all 434-factorization combos
for w1,h1 in factors_434:
    if w1<=1 or h1<=1: continue
    for w2,h2 in factors_434:
        if w2<=1 or h2<=1: continue
        m = sum(1 for i in range(336) if formula_434(i,w1,h1,w2,h2)==k3_carved_to_pt(i))
        if m > 10:
            print(f"  {w1}×{h1}→{w2}×{h2}: {m}/336 match K3 formula")
            if m == 336:
                print(f"  PERFECT MATCH! Now extract K4 perm:")
                k4_perm = [formula_434(i, w1, h1, w2, h2) - 337
                           for i in range(337, 434)]
                print(f"  K4 perm (first 10): {k4_perm[:10]}")
                if len(k4_perm) == 97 and len(set(k4_perm)) == 97 and set(k4_perm) == set(range(97)):
                    test_perm_full(k4_perm, f"434formula_{w1}x{h1}")

print("\n=== DONE ===")
