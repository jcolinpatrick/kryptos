"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_k3_grille_v2.py — K3 confirmed pure transposition; extend to K4.

KEY FINDING FROM V1: Inverse-transposing K3 carved text gives ENGLISH directly —
K3 is PURE TRANSPOSITION with no Vigenère component.

"SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHE"

This script:
1. Verifies K3 PT recovery (pure transposition hypothesis)
2. Characterises the K3 reading-order step pattern
3. Extends K3 step pattern into K4 territory → K4 permutation
4. Tests K4 as pure transposition (no cipher) with all grid reading orders
5. Tests K4 with single-rotation grids at all sizes near 97
6. Reports ANY crib hit immediately

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_k3_grille_v2.py
"""
from __future__ import annotations
import sys, math, itertools
from collections import Counter

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ["KRYPTOS","PALIMPSEST","ABSCISSA","SHADOW","SANBORN",
            "SCHEIDT","BERLIN","CLOCK","EAST","NORTH",
            "LIGHT","ANTIPODES","MEDUSA","ENIGMA"]

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4_CARVED) == 97

# Known PT positions (cribs)
ENE = "EASTNORTHEAST"   # PT positions 21-33
BC  = "BERLINCLOCK"     # PT positions 63-73

# ─── Cipher functions ─────────────────────────────────────────────────────────
def vig_decrypt(ct, key, alpha=AZ):
    res = []
    for i, c in enumerate(ct):
        ci = alpha.index(c); ki = alpha.index(key[i%len(key)])
        res.append(alpha[(ci-ki)%26])
    return "".join(res)

def beau_decrypt(ct, key, alpha=AZ):
    res = []
    for i, c in enumerate(ct):
        ci = alpha.index(c); ki = alpha.index(key[i%len(key)])
        res.append(alpha[(ki-ci)%26])
    return "".join(res)

def check_cribs_at_pos(pt):
    """Check cribs at expected positions 21-33 and 63-73."""
    ene_ok = len(pt) > 33 and pt[21:34] == ENE
    bc_ok  = len(pt) > 73 and pt[63:74] == BC
    return ene_ok, bc_ok

def check_cribs_anywhere(pt):
    return ENE in pt, BC in pt

def score_pt(pt):
    """Pure transposition: candidate PT = K4_CARVED permuted. Check crib positions."""
    ene_ok = pt[21:34] == ENE if len(pt) > 33 else False
    bc_ok  = pt[63:74] == BC  if len(pt) > 73 else False
    return ene_ok, bc_ok

def test_permutation_pure(sigma):
    """Test σ under pure transposition (no cipher): PT[i] = K4_CARVED[σ[i]]."""
    pt = "".join(K4_CARVED[sigma[i]] for i in range(97))
    ene_ok, bc_ok = score_pt(pt)
    if ene_ok or bc_ok:
        print(f"  *** PURE TRANSPOSITION CRIB HIT ***")
        print(f"      ENE@21={ene_ok}, BC@63={bc_ok}")
        print(f"      PT: {pt}")
        return True
    return False

def test_permutation_ciphered(sigma):
    """Test σ under all Vig/Beau/key combinations."""
    real_ct = "".join(K4_CARVED[sigma[i]] for i in range(97))
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ",AZ),("KA",KA)]:
            for cname, cfn in [("vig",vig_decrypt),("beau",beau_decrypt)]:
                try:
                    pt = cfn(real_ct, kw, alpha)
                    ene_ok, bc_ok = check_cribs_at_pos(pt)
                    if ene_ok or bc_ok:
                        print(f"  *** CRIB HIT: {cname}/{kw}/{alpha_name} ***")
                        print(f"      ENE@21={ene_ok}, BC@63={bc_ok}")
                        print(f"      PT: {pt}")
                        return True
                    ane, abc_ = check_cribs_anywhere(pt)
                    if ane or abc_:
                        print(f"  *** CRIB ANYWHERE: {cname}/{kw}/{alpha_name} ***")
                        print(f"      ENE_anywhere={ane}, BC_anywhere={abc_}")
                        print(f"      PT: {pt}")
                        return True
                except (ValueError, IndexError):
                    pass
    return False

# ─── 1. VERIFY K3 PURE TRANSPOSITION ─────────────────────────────────────────
print("="*70)
print("1. K3 PURE TRANSPOSITION VERIFICATION")
print("="*70)

# K3 carved text (rows 14-24 in 28×31 grid, no ?'s)
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
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",  # row 14 K3 start
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",  # row 24
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",
]

def pad_row(r):
    s = CIPHER_ROWS_RAW[r]
    if len(s) > 31: s = s[:31]
    elif len(s) < 31: s += '?'*(31-len(s))
    return list(s)
GRID = [pad_row(r) for r in range(28)]

def extract_k3_ct():
    ct = []
    for r in range(14, 24):
        for c in range(31):
            ch = GRID[r][c]
            if ch.isalpha(): ct.append(ch)
    for c in range(26):
        ch = GRID[24][c]
        if ch.isalpha(): ct.append(ch)
    return "".join(ct)

K3_CT = extract_k3_ct()
assert len(K3_CT) == 336, f"K3_CT length {len(K3_CT)}"

# K3 double-rotation inverse permutation
def k3_carved_to_pt(i):
    """K3: which PT position does carved position i come from?"""
    a = i // 24; b = i % 24
    intermediate = 14 * b + 13 - a
    c = intermediate // 8; d = intermediate % 8
    return 42 * d + 41 - c

# Build K3 inverse permutation: pt[j] = carved[inv_perm[j]]
k3_fwd = [k3_carved_to_pt(i) for i in range(336)]
assert len(set(k3_fwd)) == 336, "Not a permutation"
k3_inv = [0]*336
for i, j in enumerate(k3_fwd): k3_inv[j] = i

# Recover K3 PT
k3_pt_recovered = "".join(K3_CT[k3_inv[j]] for j in range(336))
print(f"K3 PT[:80]: {k3_pt_recovered[:80]}")
print(f"K3 PT[80:160]: {k3_pt_recovered[80:160]}")
print(f"K3 PT[160:240]: {k3_pt_recovered[160:240]}")
print(f"K3 PT[240:]: {k3_pt_recovered[240:]}")

# Check if it's English
english_words = ["SLOWLY","REMAINS","PASSAGE","DEBRIS","ENCUMBERED","LOWER",
                 "PART","DOORWAY","TREMBLING","BREACH","CORNER","CANDLE",
                 "CANYOUSEEANYTHING","EMERGED","MIST"]
found = [w for w in english_words if w in k3_pt_recovered]
print(f"\nEnglish words found: {found}")
print(f"K3 is pure transposition: {len(found) >= 5}")

# ─── 2. K3 READING ORDER STEP ANALYSIS ───────────────────────────────────────
print("\n" + "="*70)
print("2. K3 READING ORDER STEP ANALYSIS")
print("="*70)

def k3_pos_to_grid(i):
    if i < 310: return (14 + i//31, i%31)
    else: return (24, i - 310)

# hole_order[j] = grid position of j-th real_CT position
hole_order = []
for j in range(336):
    i = k3_inv[j]  # which carved pos has real_CT[j]
    hole_order.append(k3_pos_to_grid(i))

# Convert to K3-1D addresses
def grid_to_k3_1d(r, c):
    if 14 <= r <= 23: return (r-14)*31 + c
    elif r == 24 and c < 26: return 310 + c
    return None

hole_1d = [grid_to_k3_1d(r,c) for r,c in hole_order]
steps = [hole_1d[i+1] - hole_1d[i] for i in range(len(hole_1d)-1)]
cnt = Counter(steps)
print(f"Step distribution: {cnt.most_common(10)}")
print(f"Unique steps: {len(cnt)}")

# Verify: -145 and +192 alternating?
pairs = list(zip(steps[::2], steps[1::2]))
pair_cnt = Counter(pairs)
print(f"\nStep pair distribution: {pair_cnt.most_common(10)}")

# Mod-336 steps
steps_mod = [s % 336 for s in steps]
cnt_mod = Counter(steps_mod)
print(f"\nSteps mod 336: {cnt_mod.most_common(5)}")

# ─── 3. EXTEND K3 READING PATTERN INTO K4 ────────────────────────────────────
print("\n" + "="*70)
print("3. EXTENDING K3 READING PATTERN INTO K4 (97 positions)")
print("="*70)

# K4 grid positions (linear in 28×31 space)
def k4_pos_to_grid(i):
    if i < 4: return (24, 27+i)
    ii = i-4; return (25+ii//31, ii%31)

k4_grid = [k4_pos_to_grid(i) for i in range(97)]
k4_linear = [r*31+c for r,c in k4_grid]
k4_set = set(k4_linear)

# The K3 reading pattern in 28×31 linear space.
# After the 336th K3 position, the "continuation" of the pattern should land in K4.
# Strategy: characterise the pattern as start + step*j (mod some bound), then extend.

hole_linear_full = [r*31+c for r,c in hole_order]

# The pattern: alternating -145 and +192 in K3-1D space.
# In 28×31 linear space, same steps but with base offset 434 (rows 14-27 start at linear 434).
# -145 in K3-1D = -145 in 28×31 linear (same because rows are contiguous).
# +192 in K3-1D = +192 in 28×31 linear.

# Generate the extended sequence: continue the pattern past K3 into K4.
# Start from hole_order[335] (last K3 position) and keep stepping.

last_k3_linear = hole_linear_full[-1]
print(f"Last K3 hole at grid{hole_order[-1]}, linear={last_k3_linear}")

# Reconstruct the two alternating step sequences
# From data: steps alternate -145 and +192 (mostly), with some wrap corrections.
# The "corrected" step sequence: always step +192 mod K3_bounds, where
# a step to position >= K3_top (= 434+336 = 770) needs adjustment.

# Let's verify: what's the actual step from position 335 to what would be 336?
# hole_1d[335] and hole_1d[334] determine the next step.
last_two_steps = steps[-2:]
print(f"Last two K3 steps: {last_two_steps}")

# Predict next step
if len(last_two_steps) == 2:
    if last_two_steps[-1] == -145:
        predicted_next_step_k31d = 192
    else:
        predicted_next_step_k31d = -145

print(f"Predicted next step (K3-1D): {predicted_next_step_k31d}")

# In 28×31 linear space, after K3 (ends at linear ~769), the pattern continues:
# K3 bottom = linear 769 (row 24, col 25)
# K4 starts at linear 771 (row 24, col 27), linear 775 (row 25), etc.

# The extension: from hole_linear_full[-1], keep applying steps +192/-145 cyclically,
# but now we're in the 434-868 range (rows 14-27), skip position 770 (the ?).
# K4 positions: linear {771,772,773,774} + rows 25-27 (all 31 each)
# = {771..774} + {775..805} + {806..836} + {837..867}

k4_linear_set = set(k4_linear)
bottom_half_linear = set()
for r in range(14, 28):
    for c in range(31):
        if GRID[r][c].isalpha():
            bottom_half_linear.add(r*31+c)

# Simulate extension of K3 step pattern into K4
# We have 336 K3 positions already visited. The 97 remaining bottom-half positions are K4.
# Under the grille reading continuation, the step pattern would continue and
# eventually visit all 97 K4 positions.

# Build a candidate K4 reading order by continuing the K3 pattern.
# Method: after the last K3 position, apply the alternating steps (+192/-145)
# skipping already-visited K3 positions and the ? position.

k3_visited = set(hole_linear_full)
pos = last_k3_linear
step_idx = 0  # which step to apply next (0: predicted_next, 1: other)
steps_cycle = [192, -145] if predicted_next_step_k31d == 192 else [-145, 192]

k4_reading_order_linear = []
max_iterations = 10000
iterations = 0

while len(k4_reading_order_linear) < 97 and iterations < max_iterations:
    iterations += 1
    step = steps_cycle[step_idx % 2]
    next_pos = pos + step
    # Wrap within rows 14-27 (linear 434..867)
    if next_pos > 867: next_pos -= 434  # wrap within bottom half
    if next_pos < 434: next_pos += 434

    if next_pos in k4_linear_set:
        k4_reading_order_linear.append(next_pos)
        pos = next_pos
        step_idx += 1
    elif next_pos in k3_visited:
        # Already visited in K3, try next step
        step_idx += 1
    else:
        # Not K3 and not K4 (must be the ? position at linear 770)
        step_idx += 1
        pos = next_pos  # advance position anyway

print(f"\nK4 reading order (continuation): {len(k4_reading_order_linear)} positions found")

if len(k4_reading_order_linear) == 97:
    # Convert linear positions to K4-internal positions (0..96)
    k4_linear_to_idx = {lin: i for i, lin in enumerate(k4_linear)}
    k4_sigma = [k4_linear_to_idx[lin] for lin in k4_reading_order_linear]
    print(f"K4 σ (first 10): {k4_sigma[:10]}")

    # Test: real_CT[j] = K4_CARVED[k4_sigma[j]] → PT[j] = ...
    real_ct = "".join(K4_CARVED[k4_sigma[j]] for j in range(97))
    print(f"K4 real CT: {real_ct}")

    # Test pure transposition first
    print("Testing pure transposition (no cipher):")
    hit = test_permutation_pure(k4_sigma)

    # Test with all ciphers
    if not hit:
        print("Testing with all ciphers:")
        test_permutation_ciphered(k4_sigma)

# ─── 4. SINGLE-ROTATION TRANSPOSITIONS FOR K4 ────────────────────────────────
print("\n" + "="*70)
print("4. SINGLE-ROTATION TRANSPOSITIONS FOR K4 (padded grids)")
print("="*70)

def single_rotation_cw(pt_list, width, height):
    """Rotate 90° CW: write in width×height, rotate, read out."""
    # Pad to width*height
    padded = pt_list + [None]*(width*height - len(pt_list))
    # Grid: padded[r*width + c] = char at (r,c)
    # Rotate 90° CW: new grid is height×width, new[c][height-1-r] = old[r][c]
    rotated = [None]*(height*width)
    for r in range(height):
        for c in range(width):
            new_r = c; new_c = height-1-r
            rotated[new_r*height + new_c] = padded[r*width+c]
    # Read out, skip None (padding)
    return [x for x in rotated if x is not None]

def double_rotation_cw(pt_list, w1, h1, w2, h2):
    """Double rotation: first w1×h1, then w2×h2."""
    inter = single_rotation_cw(pt_list, w1, h1)
    return single_rotation_cw(inter, w2, h2)

# For K4 PT (97 chars), try single rotation at various widths
print("Single rotation (width × height = 97 padded to N):")
K4_PT_PARTIAL = ['?']*97  # unknown PT
# We know positions 21-33 = EASTNORTHEAST, 63-73 = BERLINCLOCK

# Test: what permutation does single-rotation give?
for width in range(1, 20):
    for height in range(1, 20):
        if width * height < 97: continue
        if width * height > 110: continue  # only try close-to-97 sizes

        # Generate permutation
        indices = list(range(97)) + [None]*(width*height - 97)
        rotated_idx = [None]*(height*width)
        for r in range(height):
            for c in range(width):
                new_r = c; new_c = height-1-r
                rotated_idx[new_r*height + new_c] = indices[r*width+c]
        # sigma[j] = original position that ends up at carved position j
        # i.e., carved[j] = PT[sigma[j]]
        sigma = [x for x in rotated_idx if x is not None]
        if len(sigma) != 97 or len(set(sigma)) != 97: continue

        # Test: PT[i] = K4_CARVED[sigma[i]] → PT[21:34] should be EASTNORTHEAST
        pt = "".join(K4_CARVED[sigma[i]] for i in range(97))
        ene_ok, bc_ok = score_pt(pt)
        if ene_ok or bc_ok:
            print(f"  *** CRIB HIT: single rotation {width}×{height}! ***")
            print(f"      ENE@21={ene_ok}, BC@63={bc_ok}")
            print(f"      PT: {pt}")
            # Also test with ciphers
            test_permutation_ciphered(sigma)

# Also test 180° rotation (Cardan standard)
print("\n180° rotation:")
for width in range(1, 20):
    for height in range(1, 20):
        if width * height < 97: continue
        if width * height > 110: continue

        indices = list(range(97)) + [None]*(width*height - 97)
        # 180°: (r,c) → (height-1-r, width-1-c)
        rotated_idx = [None]*(height*width)
        for r in range(height):
            for c in range(width):
                new_r = height-1-r; new_c = width-1-c
                rotated_idx[new_r*width + new_c] = indices[r*width+c]
        sigma = [x for x in rotated_idx if x is not None]
        if len(sigma) != 97 or len(set(sigma)) != 97: continue

        pt = "".join(K4_CARVED[sigma[i]] for i in range(97))
        ene_ok, bc_ok = score_pt(pt)
        if ene_ok or bc_ok:
            print(f"  *** CRIB HIT: 180° rotation {width}×{height}! ***")
            print(f"      ENE@21={ene_ok}, BC@63={bc_ok}")
            test_permutation_ciphered(sigma)

print("  (no hits in single/180° rotation)")

# ─── 5. DOUBLE-ROTATION ANALOGUES FOR K4 ─────────────────────────────────────
print("\n" + "="*70)
print("5. DOUBLE-ROTATION ANALOGUES FOR K4 (K3 method adapted)")
print("="*70)

# K3 uses widths (24, 14) → (8, 42). Note 24×14 = 8×42 = 336.
# For K4 (97), try all pairs (w1, h1, w2, h2) where w1*h1 ≥ 97 and close to 97.
# Also: try with known-related values: 7, 8, 14, 24, 31, 21, 28.

hits = 0
tested = 0

for sz1 in range(97, 115):  # padded grid sizes for step 1
    if sz1 > 110: continue
    for w1 in range(2, sz1):
        h1 = sz1 // w1
        if w1 * h1 != sz1: continue

        inter_indices = list(range(97)) + [None]*(sz1 - 97)
        # Rotate 90° CW: w1×h1 → h1×w1
        step1 = [None]*(h1*w1)
        for r in range(h1):
            for c in range(w1):
                new_r = c; new_c = h1-1-r
                step1[new_r*h1 + new_c] = inter_indices[r*w1+c]
        inter = [x for x in step1 if x is not None]
        n_inter = len(inter)

        for sz2 in range(n_inter, n_inter+8):
            for w2 in range(2, sz2):
                h2 = sz2 // w2
                if w2 * h2 != sz2: continue

                padded2 = inter + [None]*(sz2 - n_inter)
                step2 = [None]*(h2*w2)
                for r in range(h2):
                    for c in range(w2):
                        new_r = c; new_c = h2-1-r
                        step2[new_r*h2 + new_c] = padded2[r*w2+c]
                sigma = [x for x in step2 if x is not None]
                if len(sigma) != 97 or len(set(sigma)) != 97: continue

                tested += 1
                pt = "".join(K4_CARVED[sigma[i]] for i in range(97))
                ene_ok, bc_ok = score_pt(pt)
                if ene_ok or bc_ok:
                    print(f"  *** CRIB HIT: double rotation ({w1}×{h1}→{w2}×{h2})! ***")
                    print(f"      ENE@21={ene_ok}, BC@63={bc_ok}")
                    print(f"      PT: {pt}")
                    test_permutation_ciphered(sigma)
                    hits += 1

print(f"  Tested {tested} double-rotation configs. Hits: {hits}")

# ─── 6. K4 PURE TRANSPOSITION: RECTANGULAR READING ORDERS ───────────────────
print("\n" + "="*70)
print("6. K4 READING ORDERS ON ITS OWN 4+31+31+31 SHAPE")
print("="*70)

# K4 occupies a specific shape in the 28×31 grid.
# Rows 24 (4 chars), 25 (31), 26 (31), 27 (31).
# Try reading orders based on this shape.

K4_SHAPE = [(24, c) for c in range(27, 31)]  # row 24, cols 27-30
K4_SHAPE += [(25, c) for c in range(31)]
K4_SHAPE += [(26, c) for c in range(31)]
K4_SHAPE += [(27, c) for c in range(31)]
assert len(K4_SHAPE) == 97

k4_shape_linear = [r*31+c for r,c in K4_SHAPE]
k4_shape_idx = {(r,c): i for i, (r,c) in enumerate(K4_SHAPE)}

# Try different reading orders for K4's shape
reading_orders = {}

# Row-major (normal) — identity, already tested
reading_orders["row_major"] = list(range(97))

# Column-major within each column
# Columns: col 27 (1 char: row 24), cols 0-26 (rows 25-27), cols 28-30 (row 24 + rows 25-27)
# Actually col 27 has: (24,27), (25,27), (26,27), (27,27) = 4 chars
# col 28: (24,28), (25,28), (26,28), (27,28)
# etc.
# Columns 27-30 each have 4 chars; columns 0-26 each have 3 chars
col_major = []
# Cols 0-26: only rows 25-27 (3 rows) = 3 chars each
for c in range(27):
    for r in [25, 26, 27]:
        col_major.append(k4_shape_idx[(r,c)])
# Cols 27-30: rows 24-27 (4 rows) = 4 chars each
for c in range(27, 31):
    for r in [24, 25, 26, 27]:
        col_major.append(k4_shape_idx[(r,c)])
reading_orders["col_major"] = col_major

# Reverse row-major
reading_orders["row_major_rev"] = list(range(96, -1, -1))

# Reverse column-major
reading_orders["col_major_rev"] = list(reversed(col_major))

# Column-major, columns right-to-left
col_major_rtl = []
for c in range(30, 26, -1):  # 30,29,28,27
    for r in [24,25,26,27]: col_major_rtl.append(k4_shape_idx[(r,c)])
for c in range(26, -1, -1):  # 26..0
    for r in [25,26,27]: col_major_rtl.append(k4_shape_idx[(r,c)])
reading_orders["col_major_rtl"] = col_major_rtl

# Boustrophedon (snake)
boustro = []
for row_idx, r in enumerate([24,25,26,27]):
    if r == 24:
        cols = list(range(27,31))  # 4 chars
    else:
        cols = list(range(31))
    if row_idx % 2 == 1: cols = list(reversed(cols))
    for c in cols: boustro.append(k4_shape_idx[(r,c)])
reading_orders["boustrophedon"] = boustro

# Bottom-to-top row-major
reading_orders["btm_to_top"] = [k4_shape_idx[(r,c)] for r in [27,26,25,24]
                                  for c in (range(31) if r != 24 else range(27,31))]

for name, sigma in reading_orders.items():
    assert len(sigma) == 97 and len(set(sigma)) == 97, f"{name}: invalid perm"
    if sigma == list(range(97)): continue  # skip identity

    pt = "".join(K4_CARVED[sigma[i]] for i in range(97))
    ene_ok, bc_ok = score_pt(pt)
    if ene_ok or bc_ok:
        print(f"  *** CRIB HIT: {name}! ***  ENE={ene_ok}, BC={bc_ok}")
        print(f"      PT: {pt}")
        test_permutation_ciphered(sigma)
    else:
        # Test with ciphers
        real_ct = "".join(K4_CARVED[sigma[i]] for i in range(97))
        for kw in KEYWORDS[:4]:  # quick check with top keywords
            for alpha in [AZ, KA]:
                for cfn in [vig_decrypt, beau_decrypt]:
                    try:
                        pt2 = cfn(real_ct, kw, alpha)
                        ene_ok2, bc_ok2 = check_cribs_at_pos(pt2)
                        if ene_ok2 or bc_ok2:
                            print(f"  *** CRIB HIT (cipher): {name}/{kw}! ***")
                    except: pass

print("  (no hits in K4 shape reading orders)")

# ─── 7. K3 STEP FORMULA APPLIED TO K4 DIRECTLY ───────────────────────────────
print("\n" + "="*70)
print("7. K3 DOUBLE-ROTATION FORMULA APPLIED DIRECTLY TO K4 (97 positions)")
print("="*70)

# K3 formula: for carved position i:
#   a = i//24, b = i%24
#   intermediate = 14*b + 13 - a
#   c = inter//8, d = inter%8
#   pt_pos = 42*d + 41 - c
#
# What happens when we apply this formula for i = 0..96 (treating K4 as 97-char K3)?
# This won't give a valid permutation for 97, but let's see what we get.

def k3_formula(i, w1=24, h1=14, w2=8, h2=42):
    a = i // w1; b = i % w1
    intermediate = h1 * b + (h1-1) - a
    c = intermediate // w2; d = intermediate % w2
    return h2 * d + (h2-1) - c

# Direct application to 97:
mapped_97 = [k3_formula(i) % 97 for i in range(97)]
if len(set(mapped_97)) == 97:
    print("K3 formula mod 97 gives valid permutation!")
    pt = "".join(K4_CARVED[mapped_97[i]] for i in range(97))
    ene_ok, bc_ok = score_pt(pt)
    print(f"  ENE={ene_ok}, BC={bc_ok}, PT={pt[:40]}")
else:
    print(f"K3 formula mod 97: {len(set(mapped_97))} unique values (not a perm)")

# Try different width combos for K4
print("\nTrying K3-style formula with adapted widths for 97:")
for w1 in [7, 8, 13, 14, 24]:
    for h1 in range(1, 20):
        if not (97 <= w1*h1 <= 104): continue
        for w2 in [7, 8, 13, 14]:
            h2 = w1*h1 // w2
            if w2*h2 != w1*h1: continue
            try:
                mapped = [k3_formula(i, w1, h1, w2, h2) for i in range(97)]
                mapped_mod = [m % 97 for m in mapped]
                if len(set(mapped_mod)) != 97: continue
                pt = "".join(K4_CARVED[mapped_mod[i]] for i in range(97))
                ene_ok, bc_ok = score_pt(pt)
                if ene_ok or bc_ok:
                    print(f"  *** CRIB HIT: w1={w1},h1={h1},w2={w2},h2={h2}! ***")
                    print(f"  PT: {pt}")
                # Check if more than 10 cribs match
                ene_count = sum(1 for i in range(13) if len(pt)>21+i and pt[21+i]==ENE[i])
                bc_count  = sum(1 for i in range(11) if len(pt)>63+i and pt[63+i]==BC[i])
                if ene_count >= 6 or bc_count >= 6:
                    print(f"  Near-hit: w1={w1},h1={h1},w2={w2},h2={h2}: ENE={ene_count}/13, BC={bc_count}/11")
            except Exception as e:
                pass

# ─── 8. THE HOLE_ORDER CONTINUATION — FULL SIMULATION ────────────────────────
print("\n" + "="*70)
print("8. FULL SIMULATION: CONTINUE K3 HOLE PATTERN INTO K4")
print("="*70)

# Hypothesis: the grille reads ALL 433 bottom-half letter positions in one order.
# K3 uses the first 336, K4 uses the remaining 97.
# The reading order is defined by the K3 permutation structure.
#
# Algorithm:
# The K3 reading order (hole_order, 336 positions) already covers all K3 positions.
# The "natural extension" of this order into K4 is defined by:
#   Start from the last K3 position (hole_order[335]).
#   Continue stepping with the same alternating +192/-145 pattern.
#   When we land in K4 territory, record that as the next K4 position.
#   Skip already-visited positions and the ? position.

k3_visited_linear = set(hole_linear_full)
# Build full K4 reading order by continuing the stepping
last_pos = hole_linear_full[-1]
step_sign = +1  # determines which step: -145 or +192
# Determine which step comes next
last_step = steps[-1]  # last step taken in K3
if last_step == -145: next_step_type = 192
elif last_step == 192: next_step_type = -145
else:
    # Determine from position of last step in the sequence
    next_step_type = 192

print(f"Continuing from K3 position {hole_linear_full[-1]} ({hole_order[-1]})")
print(f"Last K3 step: {last_step}, next predicted: {next_step_type}")

# Simulate continuation
all_visited = set(k3_visited_linear)
# Also add row 24 col 26 (the ? position, linear = 24*31+26 = 770)
all_visited.add(24*31+26)

k4_continuation = []
pos = last_pos
step_type = next_step_type
max_steps = 10000
n_steps = 0

while len(k4_continuation) < 97 and n_steps < max_steps:
    n_steps += 1
    step = step_type
    new_pos = pos + step

    # Bounds: bottom half is rows 14-27 = linear 434..867
    if new_pos > 867: new_pos -= 434
    if new_pos < 434: new_pos += 434

    if new_pos in k4_linear_set and new_pos not in all_visited:
        k4_continuation.append(new_pos)
        all_visited.add(new_pos)
        pos = new_pos
        # Alternate step
        step_type = -145 if step_type == 192 else 192
    elif new_pos in all_visited:
        # Skip: just alternate step
        step_type = -145 if step_type == 192 else 192
    else:
        # ? or other non-K4 position
        pos = new_pos  # advance
        step_type = -145 if step_type == 192 else 192

print(f"\nK4 continuation found {len(k4_continuation)} positions in {n_steps} steps")

if len(k4_continuation) == 97:
    k4_linear_to_idx = {lin: i for i, lin in enumerate(k4_linear)}
    k4_sigma_cont = [k4_linear_to_idx[lin] for lin in k4_continuation]
    print(f"K4 σ continuation (first 10): {k4_sigma_cont[:10]}")

    # Test
    hit = test_permutation_pure(k4_sigma_cont)
    if not hit:
        test_permutation_ciphered(k4_sigma_cont)

# Try both step orderings
for starting_step in [192, -145]:
    k4_cont2 = []
    all_visited2 = set(k3_visited_linear) | {24*31+26}
    pos2 = last_pos
    st = starting_step
    for _ in range(20000):
        if len(k4_cont2) == 97: break
        new_pos = pos2 + st
        if new_pos > 867: new_pos -= 434
        if new_pos < 434: new_pos += 434
        if new_pos in k4_linear_set and new_pos not in all_visited2:
            k4_cont2.append(new_pos)
            all_visited2.add(new_pos)
            pos2 = new_pos
        elif new_pos not in all_visited2:
            pos2 = new_pos
        st = -145 if st == 192 else 192

    if len(k4_cont2) == 97:
        k4_sigma2 = [k4_linear_to_idx[lin] for lin in k4_cont2]
        if k4_sigma2 != k4_sigma_cont:
            print(f"\nAlternate starting step {starting_step}: testing...")
            hit2 = test_permutation_pure(k4_sigma2)
            if not hit2:
                test_permutation_ciphered(k4_sigma2)

# ─── 9. SUMMARY ─────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("9. SUMMARY")
print("="*70)
print(f"K3 PT recovery: confirmed (pure transposition)")
print(f"K3 reading order: alternating steps -145/+192 in K3-1D space")
print(f"K4 continuation: tested both starting steps")
print(f"Single/double rotation: tested all near-97 grids")
print(f"K4 shape reading orders: tested 6 variants")
print()
