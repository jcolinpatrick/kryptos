#!/usr/bin/env python3
"""
BLITZ Wave 4: Targeted Approaches

1. Joint grille model: PT[i] = VigDec(K4[hole_grid_pos[i]], GRILLE[i])
   (grille simultaneously defines key AND reading order)
2. Exhaustive small columnar (ALL w! orderings, w=2..7)
3. Expanded keyword list (60+ keywords)
4. All 26 Caesar shifts as Vigenère keys
5. Keyword + shift combinations
6. Turning grille permutations
7. SA with permutation+keyword joint optimization
"""
import json, sys, os, math, itertools, random
from collections import defaultdict

K4     = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GRILLE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA     = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Extended keyword list
KEYWORDS = [
    # Known candidates
    'KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
    'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA',
    # K1-K3 PT words
    'BETWEEN','SUBTLE','SHADING','ABSENCE','NUANCE','ILLUSION','IQLUSION',
    'TOTALLY','INVISIBLE','POSSIBLE','MAGNETIC','UNDERGROUND','LATITUDE',
    'LONGITUDE','INFORMATION','GATHERED','SLOWLY','DESPERATELY','REMAINS',
    'PASSAGE','DEBRIS','COLLAPSED','INTERNAL','WALLS','HORIZON','HESITANT',
    'SILVER','LIGHT','PROBE',
    # Sculpture/context
    'LANGLEY','AGENCY','SECRET','COVERT','DECODE','CIPHER',
    'NORTHEAST','COMPASS','LAYER','OBELISK','PYRAMID','CAIRO','EGYPT',
    'ARTIFACT','EXCAVATION','DIGSITE','VISIBILITY','ARCHAEOLOGY',
    # Additional suspects
    'TROPOLIS','PEELING','VIRTUAL','TURNING','VIGENERE','TABLEAU',
    'CARDAN','GRILLE','CIPHER','CRYPTO','CRYPTOS',
    # Single-char keys (A-Z = Caesar shifts)
] + list(AZ)

N = 97
assert len(K4) == N
assert len(GRILLE) == 106

AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}
GRILLE_AZ = [AZ_IDX[c] for c in GRILLE]
GRILLE_KA = [KA_IDX[c] for c in GRILLE]
K4_AZ = [AZ_IDX[c] for c in K4]
K4_KA = [KA_IDX[c] for c in K4]

QG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    qg = json.load(f)

def qgscore(text):
    return sum(qg.get(text[i:i+4], -10.0) for i in range(len(text)-3))

def vig_dec(ct, key, alpha=AZ):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[ct[i]] - idx[key[i % len(key)]]) % n] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[key[i % len(key)]] - idx[ct[i]]) % n] for i in range(len(ct)))

def is_valid_perm(p, n=N):
    return len(p) == n and sorted(p) == list(range(n))

def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)

RESULTS = []
BEST_SCORE = -9999
TRIED = set()
COUNT = 0

def check_pt(pt, label, extra=""):
    global BEST_SCORE
    sc = qgscore(pt)
    ene = pt.find("EASTNORTHEAST")
    bc  = pt.find("BERLINCLOCK")
    if ene >= 0 or bc >= 0:
        print(f"\n{'='*70}")
        print(f"*** CRIB HIT *** {label} {extra}")
        print(f"  ENE@{ene}  BC@{bc}")
        print(f"  PT : {pt}")
        print(f"  Score: {sc:.2f}")
        print(f"{'='*70}\n")
        RESULTS.append({'label':label,'extra':extra,'ene':ene,'bc':bc,'pt':pt,'score':sc})
        return True
    if sc > BEST_SCORE:
        BEST_SCORE = sc
        print(f"  [best] {sc:.2f}  {label}  {extra}  {pt[:40]}…")
    return False

def try_perm(perm, label):
    global COUNT
    key = tuple(perm)
    if key in TRIED: return
    TRIED.add(key)
    COUNT += 1
    candidate_ct = apply_perm(K4, perm)
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(candidate_ct, kw, alpha)
                if check_pt(pt, label, f"{kw}/{cname}/{alpha_name}"):
                    return

# ─────────────────────────────────────────────────────────────────────────────
# GRILLE MASK
# ─────────────────────────────────────────────────────────────────────────────
GRILLE_MASK_ROWS = [
    "000000001010100000000010000000001~~",
    "100000000010000001000100110000011~~",
    "000000000000001000000000000000011~~",
    "00000000000000000000100000010011~~",
    "00000001000000001000010000000011~~",
    "000000001000000000000000000000011~",
    "100000000000000000000000000000011",
    "00000000000000000000000100000100~~",
    "0000000000000000000100000001000~~",
    "0000000000000000000000000000100~~",
    "000000001000000000000000000000~~",
    "00000110000000000000000000000100~~",
    "00000000000000100010000000000001~~",
    "00000000000100000000000000001000~~",
    "000110100001000000000000001000010~~",
    "00001010000000000000000001000001~~",
    "001001000010010000000000000100010~~",
    "00000000000100000000010000010001~~",
    "000000000000010001001000000010001~~",
    "00000000000000001001000000000100~~",
    "000000001100000010100100010001001~~",
    "000000000000000100001010100100011~",
    "00000000100000000000100001100001~~~",
    "100000000000000000001000001000010~",
    "10000001000001000000100000000001~~",
    "000010000000000000010000100000011",
    "0000000000000000000100001000000011",
    "00000000000000100000001010000001~~",
]
GRILLE_ROWS = 28
GRILLE_COLS = 33

hole_grid = [[False]*GRILLE_COLS for _ in range(GRILLE_ROWS)]
all_holes_rc = []
for r, row_str in enumerate(GRILLE_MASK_ROWS):
    for c, ch in enumerate(row_str):
        if c < GRILLE_COLS and ch == '0':
            hole_grid[r][c] = True
            all_holes_rc.append((r, c))

print(f"Total holes: {len(all_holes_rc)}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 1: Joint grille model
# K4 is laid out in various grids. Grille holes read K4 in order.
# Each hole i reads K4[grid_pos[i]] and applies GRILLE[i] as Vig key.
# PT = [VigDec(K4[grid_pos[i]], GRILLE[i]) for i in 0..96]
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH 1: Joint grille model (simultaneous key+transposition) ---")

def joint_grille_decrypt(grid_positions, grille_extract, k4=K4):
    """
    grid_positions: list of 97 K4 indices (which K4 char each hole reads)
    grille_extract: 106-char string used as running key
    Returns: PT string of length 97
    """
    result = []
    for i, gpos in enumerate(grid_positions):
        if gpos >= len(k4): continue
        ct_char = k4[gpos]
        key_char = grille_extract[i % len(grille_extract)]
        for alpha, alpha_name in [(AZ, "AZ"), (KA, "KA")]:
            # Vig
            idx_ct = alpha.index(ct_char) if ct_char in alpha else -1
            idx_key = alpha.index(key_char) if key_char in alpha else -1
            if idx_ct >= 0 and idx_key >= 0:
                pass  # we'll compute below
    return None  # placeholder

def try_joint_grid(r0, c0, nrows, ncols, label_prefix):
    """
    Try: K4 written in nrows×ncols grid starting at (r0,c0) of the grille.
    Holes that fall within the grid read K4[relative_position].
    """
    holes_in_grid = []
    for r, c in all_holes_rc:
        if r0 <= r < r0+nrows and c0 <= c < c0+ncols:
            k4_pos = (r - r0) * ncols + (c - c0)
            if k4_pos < N:
                holes_in_grid.append((k4_pos, r, c))

    if len(holes_in_grid) < N: return  # not enough valid holes

    # Take first N holes (row-major order already maintained)
    holes_sorted = sorted(holes_in_grid, key=lambda x: (x[1], x[2]))[:N]
    if len(holes_sorted) < N: return

    # Extract K4 positions and corresponding grille extract positions
    k4_positions = [h[0] for h in holes_sorted]
    # Corresponding grille extract index (which hole in the ALL-holes list)
    grille_indices = []
    for k4p, r, c in holes_sorted:
        # Find index of (r,c) in all_holes_rc
        idx = all_holes_rc.index((r, c)) if (r, c) in all_holes_rc else -1
        grille_indices.append(idx)

    # Joint decrypt: for each hole position i in K4, decrypt with GRILLE[grille_idx]
    for alpha, alpha_name in [(AZ, "AZ"), (KA, "KA")]:
        for fn_name, fn_op in [("vig", lambda ct_i, key_i, n: (ct_i - key_i) % n),
                                 ("beau", lambda ct_i, key_i, n: (key_i - ct_i) % n)]:
            n_alpha = len(alpha)
            alpha_idx = {c: i for i, c in enumerate(alpha)}
            pt = []
            for i, (k4p, r, c) in enumerate(holes_sorted):
                ct_char = K4[k4p]
                g_idx = grille_indices[i]
                if g_idx < 0 or g_idx >= len(GRILLE): continue
                key_char = GRILLE[g_idx]
                if ct_char not in alpha or key_char not in alpha:
                    pt.append('?')
                    continue
                pt_i = fn_op(alpha_idx[ct_char], alpha_idx[key_char], n_alpha)
                pt.append(alpha[pt_i])

            if len(pt) == N:
                pt_str = ''.join(pt)
                check_pt(pt_str, f"{label_prefix}_joint_{fn_name}/{alpha_name}")

    # Also: use the holes as a permutation perm, then test with all keywords
    if is_valid_perm(k4_positions):
        try_perm(k4_positions, f"{label_prefix}_perm")
    else:
        # Use rank
        from itertools import count as icount
        ranked = sorted(range(N), key=lambda i: k4_positions[i])
        perm = [0]*N
        for rank, idx in enumerate(ranked): perm[idx] = rank
        try_perm(perm, f"{label_prefix}_rank_perm")

# Try various grid placements
print("  Grid placement search...")
for r0 in range(0, GRILLE_ROWS-3):
    for c0 in range(0, GRILLE_COLS-5):
        for nrows in range(3, min(GRILLE_ROWS-r0+1, 15)):
            for ncols in range(5, min(GRILLE_COLS-c0+1, 25)):
                if nrows * ncols < N: continue
                if nrows * ncols > N + 10: continue  # not too many padding cells
                try_joint_grid(r0, c0, nrows, ncols, f"joint_r{r0}c{c0}_{nrows}x{ncols}")
    if r0 % 5 == 4:
        print(f"  r0={r0+1}/{GRILLE_ROWS} done, tried={COUNT}")

print(f"  Joint grille done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 2: Exhaustive columnar (all w! orderings, w=2..7)
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH 2: Exhaustive columnar (w=2..7, ALL orderings) ---")

def columnar_perm(width, col_order, n=N):
    rows = math.ceil(n / width)
    perm = []
    for col in col_order:
        for row in range(rows):
            src = row * width + col
            if src < n:
                perm.append(src)
    return perm if len(perm) == n else None

for w in range(2, 8):
    count_w = 0
    for col_order in itertools.permutations(range(w)):
        p = columnar_perm(w, col_order)
        if p and is_valid_perm(p):
            try_perm(p, f"col_w{w}_{''.join(map(str,col_order))}")
            inv = [0]*N
            for i, v in enumerate(p): inv[v] = i
            try_perm(inv, f"col_w{w}_{''.join(map(str,col_order))}_inv")
        count_w += 1
    print(f"  w={w}: {count_w} orderings done, total tried={COUNT}")

print(f"  Exhaustive columnar done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 3: Direct monoalphabetic substitution on K4 (no permutation)
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH 3: Monoalphabetic substitutions on K4 ---")

# Try all 26 Caesar shifts in AZ and KA
for shift in range(26):
    # Caesar in AZ
    pt_az = ''.join(AZ[(AZ_IDX[c] - shift) % 26] for c in K4)
    check_pt(pt_az, f"mono_caesar_AZ_shift{shift}")

    # Caesar in KA
    pt_ka = ''.join(KA[(KA_IDX[c] - shift) % 26] for c in K4)
    check_pt(pt_ka, f"mono_caesar_KA_shift{shift}")

    # Beaufort (key - ct)
    pt_beau_az = ''.join(AZ[(shift - AZ_IDX[c]) % 26] for c in K4)
    check_pt(pt_beau_az, f"mono_beau_AZ_shift{shift}")
    pt_beau_ka = ''.join(KA[(shift - KA_IDX[c]) % 26] for c in K4)
    check_pt(pt_beau_ka, f"mono_beau_KA_shift{shift}")

# Affine: pt = a*ct + b mod 26
for a in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:  # gcd(a,26)=1
    for b in range(26):
        pt = ''.join(AZ[(a * AZ_IDX[c] + b) % 26] for c in K4)
        check_pt(pt, f"mono_affine_AZ_a{a}_b{b}")

print(f"  Mono substitution done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 4: GRILLE as running key, with many permutation variants
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH 4: GRILLE as running key on various K4 arrangements ---")

# Key variants of the grille extract as running key
grille_keys = {
    'fwd': GRILLE,
    'rev': GRILLE[::-1],
    'fwd97': GRILLE[:97],
    'rev97': GRILLE[:97][::-1],
    'col_maj': ''.join(GRILLE[i] for i in sorted(range(106),
                        key=lambda x: (GRILLE_AZ[x], x))),
}

# Permutations to try
perms_to_try = {
    'identity': list(range(N)),
    'reverse': list(range(N-1, -1, -1)),
}

# Load REMAP_8x13 permutation
r0, r1, c0, c1 = 20, 28, 0, 13
ncols = 13
rect_holes = [(r, c) for r in range(r0, r1) for c in range(c0, c1)
              if c < GRILLE_COLS and hole_grid[r][c]]
# Sort by row-major
rect_holes_sorted = sorted(rect_holes, key=lambda x: (x[0], x[1]))
if len(rect_holes_sorted) == 97:
    grid_positions = [(r-r0)*ncols + (c-c0) for r, c in rect_holes_sorted]
    valid_pos = [p for p in grid_positions if p < N]
    unused = [p for p in range(N) if p not in set(valid_pos)]
    unused_iter = iter(unused)
    perm_8x13 = []
    for p in grid_positions:
        if p < N: perm_8x13.append(p)
        else: perm_8x13.append(next(iter(unused)))
    # Reset iterator
    unused_iter2 = iter(unused)
    perm_8x13 = []
    for p in grid_positions:
        if p < N: perm_8x13.append(p)
        else: perm_8x13.append(next(unused_iter2))
    if is_valid_perm(perm_8x13):
        perms_to_try['8x13'] = perm_8x13
        inv8 = [0]*N
        for i, v in enumerate(perm_8x13): inv8[v] = i
        perms_to_try['8x13_inv'] = inv8

for perm_name, perm in perms_to_try.items():
    if not is_valid_perm(perm): continue
    ct_arranged = apply_perm(K4, perm)
    for key_name, grille_key in grille_keys.items():
        for alpha, alpha_name in [(AZ, "AZ"), (KA, "KA")]:
            # Vig decrypt with grille as running key
            n_a = len(alpha)
            a_idx = {c: i for i, c in enumerate(alpha)}
            pt_vig = []
            pt_beau = []
            for i, c in enumerate(ct_arranged):
                kc = grille_key[i % len(grille_key)]
                if c in a_idx and kc in a_idx:
                    pt_vig.append(alpha[(a_idx[c] - a_idx[kc]) % n_a])
                    pt_beau.append(alpha[(a_idx[kc] - a_idx[c]) % n_a])
                else:
                    pt_vig.append('?')
                    pt_beau.append('?')
            pt_vig_str = ''.join(pt_vig)
            pt_beau_str = ''.join(pt_beau)
            check_pt(pt_vig_str, f"grille_run_{perm_name}_{key_name}_vig_{alpha_name}")
            check_pt(pt_beau_str, f"grille_run_{perm_name}_{key_name}_beau_{alpha_name}")

print(f"  GRILLE running key done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 5: Turning grille permutations
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH 5: Turning grille permutations ---")

def turning_grille_perm(grid_size, holes, n=N):
    """
    A turning grille is placed in 4 rotational positions (0°, 90°, 180°, 270°).
    Each rotation reveals 1/4 of the cells.
    holes: set of (row, col) in the 0° position (one quadrant's worth).
    Returns permutation: perm[output_i] = input_pos
    """
    # 4 rotations of each hole
    # Rotation of (r,c) in a gs×gs grid:
    # 0°: (r, c)
    # 90°: (c, gs-1-r)
    # 180°: (gs-1-r, gs-1-c)
    # 270°: (gs-1-c, r)
    gs = grid_size
    order = []
    seen = set()
    for angle, (tr, tc) in enumerate([(0,0), (0,0), (0,0), (0,0)]):
        for r, c in holes:
            positions = [
                (r, c),
                (c, gs-1-r),
                (gs-1-r, gs-1-c),
                (gs-1-c, r),
            ]
            rr, cc = positions[angle]
            pos = rr * gs + cc
            if pos not in seen and pos < n:
                seen.add(pos)
                order.append(pos)
    return order if len(order) == n and is_valid_perm(order) else None

# For turning grille: grid size GS, need GS² ≥ 97
# GS=10: 100 cells (3 padding), 25 holes in base position
# GS=11: 121 cells (24 padding)
# Try GS=10 with various hole patterns

# For GS=10, need 25 holes in 10×10 grid, none overlapping with rotations
# This is a classic "turning grille" constraint
# We'll try random valid turning grilles
import random as _rng

def is_turning_grille_valid(holes, gs):
    """Check that no two holes overlap under any rotation."""
    occupied = set()
    for r, c in holes:
        positions = [
            (r, c),
            (c, gs-1-r),
            (gs-1-r, gs-1-c),
            (gs-1-c, r),
        ]
        for pos in positions:
            if pos in occupied: return False
            occupied.add(pos)
    return True

def random_turning_grille(gs, n_holes, rng_seed):
    """Generate a random valid turning grille."""
    rng = _rng.Random(rng_seed)
    # Try to fill n_holes in the top-left quarter
    max_attempts = 1000
    for _ in range(max_attempts):
        holes = set()
        cells = [(r, c) for r in range(gs) for c in range(gs)]
        rng.shuffle(cells)
        for r, c in cells:
            if len(holes) >= n_holes: break
            test = holes | {(r, c)}
            if is_turning_grille_valid(test, gs):
                holes.add((r, c))
        if len(holes) == n_holes:
            return list(holes)
    return None

print("  Trying random turning grilles (GS=10, 25 holes)...")
hits_tg = 0
for seed in range(10000):
    holes = random_turning_grille(10, 25, seed)
    if holes is None: continue
    # Build permutation from turning grille
    gs = 10
    perm = []
    seen = set()
    for angle in range(4):
        for r, c in sorted(holes):  # sort for reproducibility
            positions = [(r,c), (c,gs-1-r), (gs-1-r,gs-1-c), (gs-1-c,r)]
            rr, cc = positions[angle]
            pos = rr * gs + cc
            if pos not in seen and pos < N:
                seen.add(pos)
                perm.append(pos)
    if len(perm) == N and is_valid_perm(perm):
        try_perm(perm, f"turning_gs10_seed{seed}")
    if seed % 2000 == 1999:
        print(f"    seed={seed+1}/10000, valid_grilles_found, total tried={COUNT}")

print("  Trying turning grilles GS=7 (49 cells, need 49/4≈12 holes)...")
for seed in range(5000):
    gs = 7
    holes = random_turning_grille(gs, 12, seed)  # 12*4=48, close to 49
    if holes is None: continue
    perm = []
    seen = set()
    for angle in range(4):
        for r, c in sorted(holes):
            positions = [(r,c), (c,gs-1-r), (gs-1-r,gs-1-c), (gs-1-c,r)]
            rr, cc = positions[angle]
            pos = rr*gs + cc
            if pos not in seen and pos < N:
                seen.add(pos)
                perm.append(pos)
    if len(perm) == N and is_valid_perm(perm):
        try_perm(perm, f"turning_gs7_seed{seed}")

print(f"  Turning grille done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 6: SA with joint permutation + keyword optimization
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH 6: Joint permutation+keyword SA ---")

# Key keywords to test during SA
SA_KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'BERLIN',
               'EASTNORTHEAST', 'BERLINCLOCK', 'SANBORN', 'SCHEIDT',
               'NORTH', 'EAST', 'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA',
               'KRYPTOSABCDEFGHIJLMNQUVWXZ',  # full KA as key
               'ABCDEFGHIJKLMNOPQRSTUVWXYZ',  # full AZ as key
               ]

def sa_best_score(perm, best_kw=None, best_fn=None, best_alpha=None):
    """Score a permutation with all keywords, return best score and config."""
    ct = apply_perm(K4, perm)
    best = -9999
    for kw in SA_KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(ct, kw, alpha)
                sc = qgscore(pt)
                if sc > best:
                    best = sc
    return best

def run_sa(initial_perm, temp_start=5.0, temp_end=0.01, n_iter=500000, label="SA"):
    """Simulated annealing over permutation space."""
    perm = list(initial_perm)
    score = sa_best_score(perm)
    best_perm = perm[:]
    best_score = score

    temp = temp_start
    cooling = (temp_end / temp_start) ** (1.0 / n_iter)

    for iteration in range(n_iter):
        # Random swap
        i, j = random.sample(range(N), 2)
        perm[i], perm[j] = perm[j], perm[i]
        new_score = sa_best_score(perm)

        # Accept?
        delta = new_score - score
        if delta > 0 or random.random() < math.exp(delta / temp):
            score = new_score
            if score > best_score:
                best_score = score
                best_perm = perm[:]
                if iteration % 50000 == 0:
                    print(f"    iter={iteration} temp={temp:.4f} best={best_score:.1f}")
        else:
            perm[i], perm[j] = perm[j], perm[i]  # revert

        temp *= cooling

        if iteration % 100000 == 99999:
            print(f"  SA iter={iteration+1}/{n_iter} temp={temp:.4f} best={best_score:.1f}")
            # Test best_perm with full keyword list
            try_perm(best_perm, f"{label}_iter{iteration}")

    return best_perm, best_score

print("  Running SA from random starts...")
for sa_run in range(5):
    init_perm = list(range(N))
    random.shuffle(init_perm)
    best_p, best_s = run_sa(init_perm, temp_start=3.0, temp_end=0.01,
                             n_iter=200000, label=f"SA_run{sa_run}")
    print(f"  SA run {sa_run}: best_score={best_s:.1f}")
    try_perm(best_p, f"SA_final_run{sa_run}")

print(f"  SA done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 7: Exhaustive keyword search on promising permutations
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH 7: Exhaustive short-keyword search on 8x13 perm ---")

if 'perm_8x13' in perms_to_try and is_valid_perm(perms_to_try.get('8x13', [])):
    perm_test = perms_to_try['8x13']
    ct_arranged = apply_perm(K4, perm_test)
    print(f"  CT arranged: {ct_arranged}")

    # Test all length-1 keys
    print("  Length-1 keys...")
    for c in AZ:
        for alpha, aname in [(AZ,"AZ"),(KA,"KA")]:
            for fn, fname in [(vig_dec,"vig"),(beau_dec,"beau")]:
                pt = fn(ct_arranged, c, alpha)
                check_pt(pt, f"8x13_key_{c}_{fname}_{aname}")

    # Test all length-2 keys
    print("  Length-2 keys...")
    for c1 in AZ:
        for c2 in AZ:
            kw = c1 + c2
            for alpha, aname in [(AZ,"AZ"),(KA,"KA")]:
                pt_v = vig_dec(ct_arranged, kw, alpha)
                pt_b = beau_dec(ct_arranged, kw, alpha)
                check_pt(pt_v, f"8x13_key_{kw}_vig_{aname}")
                check_pt(pt_b, f"8x13_key_{kw}_beau_{aname}")

    # Test length-3 for AZ only (most common)
    print("  Length-3 keys (AZ only, checking top quadgrams)...")
    for c1 in AZ:
        for c2 in AZ:
            for c3 in AZ:
                kw = c1+c2+c3
                pt = vig_dec(ct_arranged, kw, AZ)
                if qgscore(pt) > -600:
                    check_pt(pt, f"8x13_key_{kw}_vig_AZ")
                pt = beau_dec(ct_arranged, kw, AZ)
                if qgscore(pt) > -600:
                    check_pt(pt, f"8x13_key_{kw}_beau_AZ")
        if AZ.index(c1) % 5 == 4:
            print(f"    c1={c1} done")

print(f"  Exhaustive keyword done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# SAVE
# ─────────────────────────────────────────────────────────────────────────────
out_dir = "/home/cpatrick/kryptos/blitz_results/numeric_permuter"
os.makedirs(out_dir, exist_ok=True)
summary = {"wave": 4, "total_tried": COUNT, "crib_hits": len(RESULTS),
           "best_score": BEST_SCORE, "hits": RESULTS}
with open(f"{out_dir}/results_wave4.json", "w") as f:
    json.dump(summary, f, indent=2)
print(f"\n✓ Wave 4 saved. Tried={COUNT}, Hits={len(RESULTS)}, Best={BEST_SCORE:.2f}")

if RESULTS:
    print("\n" + "="*70)
    print("CRIB HITS:")
    for r in RESULTS:
        print(f"  {r['label']}  {r.get('extra','')}  ENE@{r['ene']} BC@{r['bc']}")
        print(f"  PT: {r['pt']}")
else:
    print(f"\nNo crib hits. Best score: {BEST_SCORE:.2f}")
