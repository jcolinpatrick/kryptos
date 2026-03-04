#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_grille_geometry_v7.py

NEW approaches beyond v5/v6:

A. FORCED-CONSTRAINT FILTER
   For KRYPTOS/vig/AZ: sigma[29]=64 (Y forced), sigma[26,30]={82,94},
   sigma[64,70]={24,66}. Test every grille-derived candidate against these.
   Map which grille-based families could possibly satisfy them.

B. SYSTEMATIC WEIGHTED SORT (all weights 1..33)
   Sort holes by weight*r + c for weight in 1..33 (covers all
   reading directions). Convert rank to permutation. Not exhausted in v6.

C. Z/97Z ARITHMETIC (prime field)
   97 is prime. For a,b in 0..96 (a≠0): sigma[k] = (a*k + b) mod 97.
   Combined with grille: sigma_grille[k] = (a * hole_linear[k] + b) mod 97.
   Enumerate feasible (a,b) by forced constraints.

D. ANTI-DIAGONAL HOLE COUNTS → KEY
   Count holes per anti-diagonal (r+c=const, const in 0..59).
   Use non-zero counts as a transposition key.

E. GRILLE ON FULL KRYPTOS TEXT
   Kryptos has ~865 chars. Grille placed at row-offset covering K4 region
   (chars 768..864) in a physical tableau layout. Holes reveal K4 chars.

F. HOLE SUBSEQUENCES (arithmetic progressions)
   Take holes at indices 0, d, 2d, ... mod 107 for d=2..53.
   First 97 unique positions → permutation.

G. BINARY MASK AS NUMBER → PERMUTATION
   Read row-by-row to get 107 zero-positions (already have).
   Read col-by-col → different ordering. Apply affine map mod 97.

H. HOLE PAIR SUMS/PRODUCTS → PERMUTATION
   Consecutive hole pairs (h0+h1, h2+h3, ...) as linear positions, mod 97.

I. GRILLE ROW GROUPS (period-7 and period-8 structure)
   Group holes by row mod 7 (or mod 8). Each group defines a sub-sequence.
   Interleave groups to form full permutation.

J. REVERSE KRYPTOS: ENCRYPT K4 and find grille
   Under KRYPTOS/vig/AZ, what would the carved text look like if sigma=identity?
   Then check if the actual K4 is a simple transformation of that.

K. TABLEAU LETTER AT HOLE → VALUE MAPPING
   Each hole reveals a tableau letter. GE = those letters.
   Map GE[k] to AZ-rank, use as permutation seed differently.

L. SORTED HOLE SUBSETS (drop extreme holes)
   Drop top-N and bottom-N holes (by position), use middle 97.
"""

import json, sys, os, itertools, math
from collections import defaultdict, Counter

sys.path.insert(0, 'src')

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

GE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GE) == 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN',
            'SCHEIDT', 'BERLIN', 'CLOCK', 'EAST', 'NORTH',
            'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA']
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]

QG = json.load(open('data/english_quadgrams.json'))

def score_pc(text):
    n = len(text) - 3
    if n <= 0: return -10.0
    return sum(QG.get(text[i:i+4], -10.0) for i in range(n)) / n

def vig_dec(ct, key, alpha=AZ):
    ai = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(ai[ct[i]] - ai[key[i % len(key)]]) % 26] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    ai = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(ai[key[i % len(key)]] - ai[ct[i]]) % 26] for i in range(len(ct)))

RESULTS_DIR = "results/blitz_v7"
os.makedirs(RESULTS_DIR, exist_ok=True)

hits = []
best_score_seen = -10.0
tested = 0

def test_perm(sigma, label):
    """Test permutation sigma (real_CT[j] = K4[sigma[j]]) against all combos."""
    global tested, best_score_seen
    if len(sigma) != 97 or sorted(sigma) != list(range(97)):
        return None
    tested += 1
    real_ct = ''.join(K4[sigma[j]] for j in range(97))
    best_local = -10.0
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(real_ct, kw, alpha)
                sc = score_pc(pt)
                ene = pt.find("EASTNORTHEAST")
                bc  = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    print(f"\n{'!'*70}")
                    print(f"*** CRIB HIT: {label}")
                    print(f"    ENE@{ene}  BC@{bc}  score={sc:.4f}")
                    print(f"    PT: {pt}")
                    print(f"    Key:{kw} Cipher:{cname} Alpha:{alpha_name}")
                    print('!'*70)
                    hits.append({"label": label, "pt": pt, "ene": ene, "bc": bc,
                                 "score": sc, "key": kw, "cipher": cname, "alpha": alpha_name})
                    return sc
                if sc > best_local:
                    best_local = sc
    if best_local > best_score_seen:
        best_score_seen = best_local
        print(f"  NEW BEST [{label}]: {best_local:.4f}/char")
    return best_local

# ── Parse the binary mask ──────────────────────────────────────────────────
RAW_MASK = [
    "000000001010100000000010000000001",  # row 0 (row 01)
    "100000000010000001000100110000011",  # row 1
    "000000000000001000000000000000011",  # row 2
    "00000000000000000000100000010011",   # row 3 (32 chars)
    "00000001000000001000010000000011",   # row 4 (32 chars)
    "000000001000000000000000000000011",  # row 5 — NOTE: 33 chars with trailing 1
    "100000000000000000000000000000011",  # row 6
    "00000000000000000000000100000100",   # row 7 (32)
    "0000000000000000000100000001000",    # row 8 (31)
    "0000000000000000000000000000100",    # row 9 (31)
    "000000001000000000000000000000",     # row 10 (30)
    "00000110000000000000000000000100",   # row 11 (32)
    "00000000000000100010000000000001",   # row 12 (32)
    "00000000000100000000000000001000",   # row 13 (32)
    "000110100001000000000000001000010",  # row 14 (33)
    "00001010000000000000000001000001",   # row 15 (32)
    "001001000010010000000000000100010",  # row 16 (33)
    "00000000000100000000010000010001",   # row 17 (32)
    "000000000000010001001000000010001",  # row 18 (33)
    "00000000000000001001000000000100",   # row 19 (32)
    "000000001100000010100100010001001",  # row 20 (33)
    "000000000000000100001010100100011",  # row 21 (33)
    "00000000100000000000100001100001",   # row 22 (32)
    "100000000000000000001000001000010",  # row 23 (33)
    "10000001000001000000100000000001",   # row 24 (32)
    "000010000000000000010000100000011",  # row 25 (33)
    "0000000000000000000100001000000011", # row 26 (34)
    "00000000000000100000001010000001",   # row 27 (32)
]

NROWS = 28
NCOLS = 33  # max width

# Parse holes: 1=HOLE, 0=SOLID; filter c<33 for in-grid only (v6 convention → 114 holes)
holes = [(r, c) for r, row_str in enumerate(RAW_MASK)
         for c, ch in enumerate(row_str) if ch == '1' and c < 33]

print(f"Total in-grid holes (c<33): {len(holes)}")
# v6 confirmed 114 in-grid holes (106 with GE letters)
assert 110 <= len(holes) <= 120, f"Expected ~114, got {len(holes)}"

# Linear positions
hole_linear = [r * NCOLS + c for r, c in holes]

# K4 letter index
K4_POS = defaultdict(list)
for i, c in enumerate(K4):
    K4_POS[c].append(i)

print(f"K4 = {K4}")
print(f"Holes: {len(holes)}, linear range: {min(hole_linear)}..{max(hole_linear)}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH A: FORCED-CONSTRAINT ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH A: FORCED-CONSTRAINT ANALYSIS")
print("="*70)

def compute_expected_ct(kw, cipher, alpha):
    ai = {c: i for i, c in enumerate(alpha)}
    expected = {}
    for start, text in CRIBS:
        for j, pt_ch in enumerate(text):
            pos = start + j
            ki = ai[kw[pos % len(kw)]]
            pi = ai[pt_ch]
            if cipher == "vig":
                expected[pos] = alpha[(pi + ki) % 26]
            else:
                expected[pos] = alpha[(ki - pi) % 26]
    return expected

# Compute forced constraints for KRYPTOS/vig/AZ
print("\nKRYPTOS/vig/AZ forced constraints:")
exp_kryptos = compute_expected_ct("KRYPTOS", "vig", AZ)
forced = {}
ambiguous = {}
for pos in sorted(exp_kryptos):
    ch = exp_kryptos[pos]
    candidates = K4_POS[ch]
    if len(candidates) == 1:
        forced[pos] = candidates[0]
        print(f"  FORCED: sigma[{pos}] = {candidates[0]} ({ch})")
    else:
        ambiguous[pos] = candidates
        print(f"  sigma[{pos}] ∈ {candidates} ({ch}, {len(candidates)} choices)")

print(f"\nFORCED: {len(forced)}, AMBIGUOUS: {len(ambiguous)}")
print(f"Forced assignments: {forced}")

# Check Y-position (sigma[29] = 64 typically)
y_pos = K4_POS.get('Y', [])
print(f"\nY positions in K4: {y_pos}")
if len(y_pos) == 1:
    print(f"sigma[29] is FORCED = {y_pos[0]}")

# Now: for any candidate permutation family, check if sigma[29] = y_pos[0]
# This is the PRIMARY filter
forced_sigma_29 = y_pos[0] if len(y_pos) == 1 else None

# Also for KRYPTOS/vig/KA and KRYPTOS/beau/AZ
for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
    for cipher in ['vig', 'beau']:
        for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
            exp = compute_expected_ct(kw, cipher, alpha)
            fc = sum(1 for pos,ch in exp.items() if len(K4_POS[ch]) == 1)
            feasible = all(len(K4_POS.get(ch, [])) >= 1 for ch in exp.values())
            # Check multiplicity
            need = Counter(exp.values())
            ok = all(len(K4_POS.get(ch, [])) >= cnt for ch, cnt in need.items())
            if ok:
                print(f"  {kw}/{cipher}/{alpha_name}: feasible, {fc} forced positions")

# ── Helper: check if candidate sigma satisfies all forced crib constraints ──
def satisfies_forced(sigma, kw, cipher, alpha):
    """Return fraction of crib positions correctly mapped."""
    exp = compute_expected_ct(kw, cipher, alpha)
    hits_count = 0
    for pos, ch in exp.items():
        if pos < len(sigma) and sigma[pos] < len(K4):
            if K4[sigma[pos]] == ch:
                hits_count += 1
    return hits_count / len(exp)

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH B: SYSTEMATIC WEIGHTED SORT (weights 1..33)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH B: WEIGHTED SORT of holes (weight*r + c, weight=1..33)")
print("="*70)

def holes_to_perm_weighted(weight, subset=None):
    """Sort holes by weight*r + c, use their K4 index (hole_k → K4 pos k)."""
    h = subset if subset is not None else holes
    n = min(97, len(h))
    # Sort by weighted coordinate
    sorted_h = sorted(range(len(h)), key=lambda i: weight * h[i][0] + h[i][1])
    # sigma[k] = index-into-K4 of the k-th hole in this sorted order
    # But we need sigma to be a permutation of 0..96
    # Interpretation: hole k (in sorted order) reveals K4 character at position k
    # i.e., sigma[k] = sorted_h[k] (if sorted_h[k] < 97)
    # OR: sigma[sorted_h[k]] = k
    # Let's use: the k-th hole in sorted order IS at K4 position k
    # So real_CT[k] = K4[sorted_h[k]]
    return sorted_h[:97]

best_B = {}
for w in range(1, 34):
    # Sort all holes by w*r+c, take first 97 as sigma
    sorted_idx = sorted(range(len(holes)), key=lambda i: w * holes[i][0] + holes[i][1])
    sigma = sorted_idx[:97]
    if sorted(sigma) == list(range(97)):
        sc = test_perm(sigma, f"B-w{w}-asc")
    # Also try descending
    sorted_idx_desc = sorted(range(len(holes)), key=lambda i: -(w * holes[i][0] + holes[i][1]))
    sigma_d = sorted_idx_desc[:97]
    if sorted(sigma_d) == list(range(97)):
        sc = test_perm(sigma_d, f"B-w{w}-desc")

    # Alternative: rank of k-th hole gives sigma[k]
    # First 97 holes (reading order), ranked by w*r+c
    sub97 = holes[:97]
    ranks = sorted(range(97), key=lambda k: w * sub97[k][0] + sub97[k][1])
    # ranks[k] = the position in reading order of the k-th element in weighted order
    # sigma[k] = ranks[k] means real_CT[k] = K4[ranks[k]]
    sc = test_perm(ranks, f"B-w{w}-rank-fwd")

    # Inverse: sigma[ranks[k]] = k
    inv = [0] * 97
    for k, r in enumerate(ranks):
        inv[r] = k
    test_perm(inv, f"B-w{w}-rank-inv")

print(f"  [B done, tested {tested} perms so far]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH C: Z/97Z ARITHMETIC (prime field)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH C: Z/97Z arithmetic on hole positions")
print("="*70)

# sigma[k] = (a * hole_linear[k] + b) mod 97
# For forced constraint: if sigma[29] = 64 is forced, need
#   (a * hole_linear[29] + b) mod 97 = 64
# This constrains (a, b) to a line in Z/97Z x Z/97Z

h_lin_97 = [x % 97 for x in hole_linear]
print(f"  First 30 hole_linear mod 97: {h_lin_97[:30]}")

valid_affine = 0
for a in range(1, 97):  # a != 0 (mod 97)
    for b in range(97):
        # sigma[k] = (a * h_lin_97[k] + b) % 97 for k=0..96
        sigma = [(a * h_lin_97[k] + b) % 97 for k in range(97)]
        if len(set(sigma)) == 97:  # valid permutation
            valid_affine += 1
            # Check forced constraint
            if forced_sigma_29 is not None and sigma[29] != forced_sigma_29:
                continue  # skip — violates constraint
            test_perm(sigma, f"C-a{a}-b{b}")
        if a == 1 and b == 0:
            print(f"  Identity check: sigma[29]={sigma[29]} (want {forced_sigma_29})")

print(f"  [C done, {valid_affine} valid affine perms found]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH D: ANTI-DIAGONAL HOLE COUNTS → TRANSPOSITION KEY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH D: Anti-diagonal hole counts as transposition key")
print("="*70)

# Anti-diagonal k: all (r, c) with r + c = k, for k in 0..59
max_diag = NROWS + NCOLS - 2  # = 27 + 32 = 59
holes_per_antidiag = [0] * (max_diag + 1)
for r, c in holes:
    d = r + c
    if d <= max_diag:
        holes_per_antidiag[d] += 1

print(f"  Anti-diag hole counts: {holes_per_antidiag}")
print(f"  Non-zero: {[(d, cnt) for d, cnt in enumerate(holes_per_antidiag) if cnt > 0]}")

# Use non-zero anti-diagonal counts as transposition key
nonzero_diag = [cnt for cnt in holes_per_antidiag if cnt > 0]
print(f"  Non-zero key length: {len(nonzero_diag)}, values: {nonzero_diag}")

def columnar_perm(n, key):
    """Columnar transposition: write n chars into len(key) cols, read by sorted key."""
    ncols = len(key)
    nrows = (n + ncols - 1) // ncols
    order = sorted(range(ncols), key=lambda i: key[i])
    sigma = []
    for col in order:
        for row in range(nrows):
            pos = row * ncols + col
            if pos < n:
                sigma.append(pos)
    return sigma

if 6 <= len(nonzero_diag) <= 25:
    sig_d = columnar_perm(97, nonzero_diag)
    if len(sig_d) == 97:
        test_perm(sig_d, "D1-antidiag-key")
        inv_d = [0]*97
        for i,v in enumerate(sig_d): inv_d[v] = i
        test_perm(inv_d, "D1-antidiag-key-inv")

# Also: holes per main diagonal (c - r = const)
holes_per_maindiag = defaultdict(int)
for r, c in holes:
    holes_per_maindiag[c - r] += 1
mdiag_counts = [holes_per_maindiag[k] for k in sorted(holes_per_maindiag)]
print(f"  Main-diag non-zero count: {len(mdiag_counts)}, vals: {mdiag_counts}")
if 6 <= len(mdiag_counts) <= 25:
    sig_m = columnar_perm(97, mdiag_counts)
    if len(sig_m) == 97:
        test_perm(sig_m, "D2-maindiag-key")

print(f"  [D done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH E: GRILLE ON FULL KRYPTOS TEXT (physical overlay)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH E: Grille on full Kryptos text overlay")
print("="*70)

# Full Kryptos sculpture has ~865 chars including K1+K2+K3+K4.
# K4 occupies positions 768..864 (97 chars).
# If the physical text is laid out in rows of width W, K4 starts
# at row R = 768 // W, col C = 768 % W.
# The 28×33 grille covers tableau rows; we want to find a placement
# where exactly 97 holes land on K4 characters.

for W in range(25, 45):
    k4_start = 768
    k4_end = 865  # exclusive
    # K4 chars occupy positions k4_start..k4_end-1 in 1D
    # In a width-W grid: position p → (p//W, p%W)
    k4_cells = set((p // W, p % W) for p in range(k4_start, k4_end))

    # Try placing the 28×33 grille at offset (dr, dc) on the full text grid
    k4_row_min = k4_start // W
    k4_row_max = (k4_end - 1) // W

    for dr in range(max(0, k4_row_min - NROWS + 1), k4_row_min + 2):
        for dc in range(-5, 5):
            # Hole at (r, c) in grille → text pos at (r+dr, c+dc) in grid
            landing = []
            for gr, gc in holes:
                tr, tc = gr + dr, gc + dc
                if tc < 0 or tc >= W:
                    continue
                p = tr * W + tc
                if k4_start <= p < k4_end:
                    k4_idx = p - k4_start
                    landing.append(k4_idx)

            if len(landing) == 97 and len(set(landing)) == 97:
                sigma = landing
                test_perm(sigma, f"E-W{W}-dr{dr}-dc{dc}")
            elif len(set(landing)) > 90:
                print(f"  Close: W={W} dr={dr} dc={dc} → {len(landing)} holes, {len(set(landing))} unique")

print(f"  [E done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH F: HOLE SUBSEQUENCES (arithmetic progressions)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH F: Hole subsequences via arithmetic progressions")
print("="*70)

N_holes = len(holes)

# For step d, take holes at indices 0, d, 2d, ... (mod N_holes)
# until we have 97 unique K4-positions (using linear mod 97)
valid_F = 0
for d in range(2, N_holes):
    if math.gcd(d, N_holes) != 1 and d != 1:
        # Might not cover all 107 holes; still try
        pass
    seq = []
    seen = set()
    idx = 0
    for _ in range(N_holes * 2):
        hidx = (idx) % N_holes
        v = hole_linear[hidx] % 97
        if v not in seen:
            seen.add(v)
            seq.append(v)
        if len(seq) == 97:
            break
        idx += d
    if len(seq) == 97 and len(set(seq)) == 97:
        valid_F += 1
        test_perm(seq, f"F-step{d}")

print(f"  [F done, {valid_F} valid AP perms]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH G: BINARY MASK COLUMN-MAJOR READING
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH G: Column-major mask reading → permutation")
print("="*70)

# Read holes in column-major order (col 0 top-to-bottom, then col 1, ...)
holes_colmajor = sorted(holes, key=lambda rc: (rc[1], rc[0]))
hcm_linear = [r * NCOLS + c for r, c in holes_colmajor]

# Try various: first 97, last 97, skip-k
for skip in range(0, min(11, len(holes_colmajor) - 97 + 1)):
    sub = hcm_linear[skip:skip+97]
    mod97 = [x % 97 for x in sub]
    if len(set(mod97)) == 97:
        test_perm(mod97, f"G-colmajor-skip{skip}-mod97")

    # Rank-based
    sub_holes = holes_colmajor[skip:skip+97]
    # sigma[k] = rank of k-th reading-order hole in colmajor ordering
    reading_order = {(r,c): i for i, (r,c) in enumerate(holes)}
    colmajor_rank = {(r,c): i for i, (r,c) in enumerate(holes_colmajor)}

    # For first-97 in row-major reading, what is their col-major rank?
    first97_rm = holes[:97]
    sigma_G = [colmajor_rank.get(h, -1) for h in first97_rm]
    if all(0 <= x < len(holes) for x in sigma_G):
        # Normalize: these are ranks 0..106; we need 0..96
        # Only valid if all sigma values are < 97
        if max(sigma_G) < 97 and len(set(sigma_G)) == 97:
            test_perm(sigma_G, f"G-rm-to-cm-rank-skip{skip}")

print(f"  [G done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH H: HOLE PAIR OPERATIONS → PERMUTATION
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH H: Hole pair operations")
print("="*70)

# Pairs of consecutive holes: (hole[0], hole[1]), (hole[2], hole[3]), ...
# Each pair (r1,c1),(r2,c2) gives a value: f(r1,c1,r2,c2) mod 97
pairs = [(holes[i], holes[i+1]) for i in range(0, len(holes)-1, 2)]
print(f"  Pairs: {len(pairs)} (from {len(holes)} holes)")

pair_formulas = {
    'sum-lin': lambda a, b: (a[0]*NCOLS+a[1] + b[0]*NCOLS+b[1]),
    'diff-lin': lambda a, b: abs(a[0]*NCOLS+a[1] - b[0]*NCOLS+b[1]),
    'prod-rc': lambda a, b: a[0]*b[1] + a[1]*b[0],
    'r1c2': lambda a, b: a[0]*NCOLS + b[1],
    'r2c1': lambda a, b: b[0]*NCOLS + a[1],
    'sum-r': lambda a, b: a[0] + b[0],
    'sum-c': lambda a, b: a[1] + b[1],
}

for fname, f in pair_formulas.items():
    vals = [f(pairs[i][0], pairs[i][1]) % 97 for i in range(min(49, len(pairs)))]
    # We need 97 values (48 pairs = 96 values; need 1 more)
    if len(vals) >= 48:
        # Take 97 from pairs overlapping by 1
        vals97 = []
        seen_h = set()
        for i in range(len(holes)-1):
            v = f(holes[i], holes[i+1]) % 97
            if v not in seen_h:
                seen_h.add(v)
                vals97.append(v)
            if len(vals97) == 97:
                break
        if len(vals97) == 97 and len(set(vals97)) == 97:
            test_perm(vals97, f"H-pair-{fname}")

print(f"  [H done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH I: ROW-GROUP INTERLEAVING (period 7 and 8)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH I: Row-group interleaving (mod-7 and mod-8)")
print("="*70)

for period in [7, 8, 6, 9, 13]:
    # Group holes by row mod period
    groups = defaultdict(list)
    for r, c in holes:
        groups[r % period].append((r, c))

    # Interleave: take group 0 first, then group 1, etc.
    for group_order in [list(range(period)), list(reversed(range(period)))]:
        interleaved = []
        for g in group_order:
            interleaved.extend(groups[g])

        # Convert to linear mod 97
        lin = [(r*NCOLS+c) % 97 for r, c in interleaved]
        seen_I = set()
        dedup = []
        for v in lin:
            if v not in seen_I:
                seen_I.add(v)
                dedup.append(v)
            if len(dedup) == 97:
                break

        if len(dedup) == 97 and len(set(dedup)) == 97:
            test_perm(dedup, f"I-p{period}-gorder{group_order[0]}")

        # Take first 97 of interleaved
        if len(interleaved) >= 97:
            sub97 = interleaved[:97]
            lin97 = [(r*NCOLS+c) % 97 for r, c in sub97]
            if len(set(lin97)) == 97:
                test_perm(lin97, f"I-p{period}-first97-gorder{group_order[0]}")

print(f"  [I done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH J: REVERSE ANALYSIS — what sigma would KRYPTOS/vig/AZ need?
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH J: Reverse analysis — compute sigma that yields English")
print("="*70)

# Under KRYPTOS/vig/AZ, if we knew the plaintext, we could compute real_CT
# and then sigma = argsort(K4, real_CT).
# We know 24 PT chars. For the remaining 73, what structure does sigma need?

exp = compute_expected_ct("KRYPTOS", "vig", AZ)
print(f"  Expected real_CT at 24 crib positions (KRYPTOS/vig/AZ):")
for pos in sorted(exp):
    print(f"    real_CT[{pos}] = {exp[pos]}")

# The 24 forced sigma values (where we know exactly which K4 char to use)
print("\n  Forced sigma mappings:")
forced_sigma = {}
for pos, ch in exp.items():
    cands = K4_POS[ch]
    if len(cands) == 1:
        forced_sigma[pos] = cands[0]
        print(f"    sigma[{pos}] = {cands[0]} (K4[{cands[0]}]='{ch}' unique)")

# For ambiguous positions, try all combinations
# Limit to small product
amb_pos = {pos: K4_POS[exp[pos]] for pos in exp if len(K4_POS[exp[pos]]) > 1}
print(f"\n  Ambiguous positions: {len(amb_pos)}")
total_combos = 1
for pos, cands in sorted(amb_pos.items()):
    print(f"    sigma[{pos}] ∈ {cands}")
    total_combos *= len(cands)
print(f"  Total partial combos (before injectivity): {total_combos}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH K: GE LETTER FREQUENCIES → PERMUTATION SEED
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH K: GE letter operations → permutation")
print("="*70)

# K1: First occurrence positions of each letter in GE (sorted by letter)
first_occ = {}
for i, ch in enumerate(GE):
    if ch not in first_occ:
        first_occ[ch] = i

# Sort letters by first occurrence position → order them 0..24 (T is absent)
letters_by_occ = sorted(first_occ.keys(), key=lambda ch: first_occ[ch])
print(f"  Letters by first occurrence in GE: {letters_by_occ}")
print(f"  Missing: {[ch for ch in AZ if ch not in first_occ]}")

# K2: Use GE as a number base-25 (T absent) → permutation of 0..96?
# Map each GE char to its index in letters_by_occ (0..24)
ge_to_idx = {ch: i for i, ch in enumerate(letters_by_occ)}
ge_num_vals = [ge_to_idx[ch] for ch in GE]

# Treat consecutive pairs as base-25 numbers mod 97
pair_vals = [(ge_num_vals[i] * 25 + ge_num_vals[i+1]) % 97
             for i in range(0, len(GE)-1, 2)]
seen_K = set()
perm_K2 = []
for v in pair_vals:
    if v not in seen_K:
        seen_K.add(v)
        perm_K2.append(v)
if len(perm_K2) == 97 and len(set(perm_K2)) == 97:
    test_perm(perm_K2, "K2-GE-base25-pairs")

# K3: Cumulative product mod 97
cp = 1
cp_perm = []
seen_K3 = set()
for v in ge_num_vals:
    cp = (cp * (v + 1)) % 97
    if cp > 0 and cp-1 not in seen_K3:
        seen_K3.add(cp-1)
        cp_perm.append(cp-1)
    if len(cp_perm) == 97:
        break
if len(cp_perm) == 97 and len(set(cp_perm)) == 97:
    test_perm(cp_perm, "K3-GE-cumprod-mod97")

# K4: GE chars as Vigenère key applied to AZ → get numeric sequence
for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
    ai = {c: i for i, c in enumerate(alpha)}
    ge_alpha_vals = [ai.get(ch, 0) for ch in GE[:97]]
    # These are values 0..25; use as position sequence with dedup
    seen_K4 = set()
    perm_K4 = []
    for v in ge_alpha_vals:
        # Map 0..25 to 0..96 by scaling? Or use cumulative?
        # Direct: only if values are < 97 (they are, 0..25)
        # Not a permutation of 0..96 directly; need different mapping
        pass

    # K4b: argsort of GE[:97]
    argsort = sorted(range(97), key=lambda k: (AZ.index(GE[k]), k))
    test_perm(argsort, f"K4b-argsort-GE97-{alpha_name}")
    # Inverse
    inv_K4b = [0]*97
    for i, v in enumerate(argsort): inv_K4b[v] = i
    test_perm(inv_K4b, f"K4b-argsort-GE97-{alpha_name}-inv")

print(f"  [K done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH L: SORTED HOLE SUBSETS (drop extremes)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH L: Drop extreme holes, use middle 97")
print("="*70)

n_extra = len(holes) - 97  # e.g., 10
print(f"  Extra holes: {n_extra}")

# Sort holes by linear position
holes_sorted = sorted(holes, key=lambda rc: rc[0]*NCOLS + rc[1])

# For each split (drop_top, drop_bot) where drop_top+drop_bot = n_extra:
for drop_top in range(n_extra + 1):
    drop_bot = n_extra - drop_top
    if drop_bot < 0:
        continue
    middle = holes_sorted[drop_top:drop_top+97] if drop_bot == 0 else holes_sorted[drop_top:-(drop_bot)]
    if len(middle) != 97:
        continue
    # Use their positions in original reading order as sigma
    reading_rank = {(r,c): i for i, (r,c) in enumerate(holes)}
    sigma_L = [reading_rank.get(h, -1) for h in middle]
    if len(set(sigma_L)) == 97 and all(0 <= x < 97 for x in sigma_L):
        test_perm(sigma_L, f"L-drop{drop_top}top-{drop_bot}bot-rdrank")

    # Also: these 97 holes in their natural reading order
    middle_sorted_by_read = sorted(middle, key=lambda rc: rc[0]*NCOLS + rc[1])
    lin_mod97 = [(r*NCOLS+c) % 97 for r, c in middle_sorted_by_read]
    if len(set(lin_mod97)) == 97:
        test_perm(lin_mod97, f"L-drop{drop_top}top-{drop_bot}bot-mod97")

print(f"  [L done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH M: HOLE POSITIONS RELATIVE TO PERIOD-8 ROWS
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH M: Period-8 structure (rows F=5, N=13, V=21)")
print("="*70)

# Period-8 anomaly rows: 5 (F), 13 (N), 21 (V)
p8_rows = {5, 13, 21}
p8_holes = [(r, c) for r, c in holes if r in p8_rows]
other_holes_p8 = [(r, c) for r, c in holes if r not in p8_rows]
print(f"  Holes in period-8 rows: {len(p8_holes)}, other: {len(other_holes_p8)}")

# M1: P8 holes first, then others (or interleaved)
for order_name, ordered in [
    ("p8first", p8_holes + other_holes_p8),
    ("othfirst", other_holes_p8 + p8_holes),
]:
    lin = [(r*NCOLS+c) % 97 for r, c in ordered[:97]]
    if len(set(lin)) == 97:
        test_perm(lin, f"M1-{order_name}")
    seen_M = set()
    dedup_M = []
    for r, c in ordered:
        v = (r*NCOLS+c) % 97
        if v not in seen_M:
            seen_M.add(v)
            dedup_M.append(v)
        if len(dedup_M) == 97: break
    if len(dedup_M) == 97 and len(set(dedup_M)) == 97:
        test_perm(dedup_M, f"M1-{order_name}-dedup")

# M2: Sort holes by (distance from nearest p8 row, then row, col)
def dist_to_p8(r):
    return min(abs(r - pr) for pr in p8_rows)

holes_by_p8dist = sorted(holes, key=lambda rc: (dist_to_p8(rc[0]), rc[0], rc[1]))
lin_M2 = [(r*NCOLS+c) % 97 for r, c in holes_by_p8dist[:97]]
if len(set(lin_M2)) == 97:
    test_perm(lin_M2, "M2-by-p8dist")

print(f"  [M done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH N: CONSTRAINT-GUIDED ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH N: Constraint-guided sigma enumeration (KRYPTOS/vig/AZ)")
print("="*70)

# For KRYPTOS/vig/AZ, we know:
#   sigma[29] = 64 (Y forced)
#   sigma[26] ∈ {82, 94} (C)
#   sigma[30] = other C position
#   sigma[64] ∈ {24, 66} (V)
#   sigma[70] = other V position
#
# Question: which grille reading orders give sigma[29] = 64?
# I.e., which orderings put hole #29 (or position 29) at linear_pos 64?

print(f"\n  Holes[29] = {holes[29]} → linear = {holes[29][0]*NCOLS+holes[29][1]}")
print(f"  Need sigma[29] = {forced_sigma_29} for KRYPTOS/vig/AZ")
print(f"  This means: K4[sigma[29]] = K4[{forced_sigma_29}] = '{K4[forced_sigma_29] if forced_sigma_29 else '?'}'")

# Check all weighted orderings for sigma[29] == 64
print("\n  Checking which weighted orderings give sigma[29]=64...")
matching_weights = []
for w in range(1, 200):
    sorted_idx = sorted(range(len(holes)), key=lambda i: w * holes[i][0] + holes[i][1])
    if len(sorted_idx) >= 97:
        sigma_N = sorted_idx[:97]
        if sorted(sigma_N) == list(range(97)) and forced_sigma_29 is not None:
            if sigma_N[29] == forced_sigma_29:
                matching_weights.append(w)

if matching_weights:
    print(f"  Weights giving sigma[29]={forced_sigma_29}: {matching_weights}")
    for w in matching_weights:
        sorted_idx = sorted(range(len(holes)), key=lambda i: w * holes[i][0] + holes[i][1])
        test_perm(sorted_idx[:97], f"N-forced-weight{w}")
else:
    print(f"  No weights 1..199 give sigma[29]={forced_sigma_29} for valid perms")

# Check: for the rank-based approach (sigma[k] = rank of hole k in sorted order),
# which weights give rank[29] == 64?
print("\n  Checking rank-based orderings...")
matching_rank_weights = []
for w in range(1, 200):
    ranks = sorted(range(min(97, len(holes))), key=lambda k: w * holes[k][0] + holes[k][1])
    # ranks[k] = index (in reading order) that goes to position k in sorted order
    # So sigma[k] = ranks[k]
    if forced_sigma_29 is not None and len(ranks) > 29 and ranks[29] == forced_sigma_29:
        matching_rank_weights.append(w)

if matching_rank_weights:
    print(f"  Rank-weights giving sigma[29]={forced_sigma_29}: {matching_rank_weights}")
    for w in matching_rank_weights:
        ranks = sorted(range(97), key=lambda k: w * holes[k][0] + holes[k][1])
        test_perm(ranks, f"N-rank-forced-w{w}")

print(f"  [N done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH O: HOLE COORDINATE → K4 INDEX VIA MODULAR INVERSE
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH O: Modular inverse mappings in Z/97Z")
print("="*70)

# Since 97 is prime, every non-zero element has a multiplicative inverse
def modinv(a, m):
    return pow(a, m-2, m)

# For each hole k (0..96), compute sigma[k] = modinv(hole_linear[k] % 97 or +1, 97)
# or other modular functions
modinv_vals = []
seen_O = set()
for lin in hole_linear[:97]:
    v = lin % 97
    if v == 0:
        mv = 0
    else:
        mv = modinv(v, 97)
    if mv not in seen_O:
        seen_O.add(mv)
        modinv_vals.append(mv)

if len(modinv_vals) == 97 and len(set(modinv_vals)) == 97:
    test_perm(modinv_vals, "O1-modinv-hole-linear")

# Power mapping: sigma[k] = hole_linear[k]^2 mod 97
pow2_vals = [(lin**2) % 97 for lin in hole_linear[:97]]
if len(set(pow2_vals)) == 97:
    test_perm(pow2_vals, "O2-hole-linear-squared")

# Square root: sigma[k] = sqrt(hole_linear[k]) mod 97 (if exists)
# In Z/97Z, x^48 gives the Legendre symbol; x^((97+1)/4) gives sqrt if 97≡3 mod 4
# 97 mod 4 = 1, so different formula needed; skip for now

# Primitive root approach: 5 is a primitive root mod 97
# sigma[k] = 5^(hole_linear[k] mod 96) mod 97 (discrete log domain)
pr = 5
disc_exp = [(pr**((lin) % 96)) % 97 for lin in hole_linear[:97]]
if len(set(disc_exp)) == 97:
    test_perm(disc_exp, "O3-primroot5-exp")

print(f"  [O done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH P: ROW-RANGE SUBSETS OF HOLES
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH P: Holes from specific row ranges")
print("="*70)

# Maybe only holes in certain rows define the permutation
for r_start in range(0, NROWS - 10):
    for r_end in range(r_start + 10, NROWS + 1):
        sub = [(r, c) for r, c in holes if r_start <= r < r_end]
        if len(sub) < 97:
            continue
        # Take first 97 in reading order
        sub_sorted = sorted(sub, key=lambda rc: (rc[0], rc[1]))[:97]
        lin_P = [(r*NCOLS+c) % 97 for r, c in sub_sorted]
        if len(set(lin_P)) == 97:
            test_perm(lin_P, f"P-rows{r_start}-{r_end}")

print(f"  [P done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH Q: GRILLE COMPLEMENT (solid cells) as permutation
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH Q: Solid (non-hole) cell sequences")
print("="*70)

# All grid positions in 28×33 that are NOT holes
all_positions = [(r, c) for r in range(NROWS) for c in range(NCOLS)]
hole_set = set(holes)
solid_cells = [(r, c) for r, c in all_positions if (r, c) not in hole_set]
print(f"  Total grid cells: {NROWS*NCOLS}, holes: {len(holes)}, solid: {len(solid_cells)}")

# Take first 97 solid cells (mod 97)
solid_lin = [(r*NCOLS+c) % 97 for r, c in solid_cells[:97]]
if len(set(solid_lin)) == 97:
    test_perm(solid_lin, "Q1-solid-first97-mod97")

# Rank of k-th solid cell among all solid cells
if len(solid_cells) >= 97:
    sigma_Q = list(range(97))  # solid_cells are already in reading order
    # Actually: sigma[k] = rank of k-th solid cell? That's just identity...
    # More interesting: rank of solid cell k in col-major order
    sc_colmajor = {(r,c): i for i,(r,c) in enumerate(sorted(solid_cells, key=lambda rc:(rc[1],rc[0])))}
    sigma_Qb = [sc_colmajor.get(solid_cells[k], -1) for k in range(97)]
    if all(0 <= x < len(solid_cells) for x in sigma_Qb):
        # Normalize to 0..96 if possible
        if max(sigma_Qb) < 97 and len(set(sigma_Qb)) == 97:
            test_perm(sigma_Qb, "Q2-solid-colmajor-rank")

print(f"  [Q done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH R: HOLE SEQUENCE AS SHIFT/ROTATION PERMUTATION
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH R: Hole-derived rotation and shift permutations")
print("="*70)

# R1: sigma[k] = (k + hole_linear[k]) mod 97
r1 = [(k + hole_linear[k]) % 97 for k in range(97)]
if len(set(r1)) == 97:
    test_perm(r1, "R1-k+hlin-mod97")

# R2: sigma[k] = (hole_linear[k] - k) mod 97
r2 = [(hole_linear[k] - k) % 97 for k in range(97)]
if len(set(r2)) == 97:
    test_perm(r2, "R2-hlin-k-mod97")

# R3: sigma[k] = (k * hole_linear[k]) mod 97
r3 = [(k * hole_linear[k]) % 97 for k in range(97)]
if len(set(r3)) == 97:
    test_perm(r3, "R3-k*hlin-mod97")

# R4: sigma[k] = k XOR (hole_linear[k] mod 97)
r4 = [k ^ (hole_linear[k] % 97) for k in range(97)]
if max(r4) < 97 and len(set(r4)) == 97:
    test_perm(r4, "R4-k-xor-hlin97")

# R5: Rotation by constant: sigma[k] = (k + C) mod 97 for C = mode of hole_linear mod 97
from statistics import mode as stat_mode
try:
    C = stat_mode([x % 97 for x in hole_linear])
    r5 = [(k + C) % 97 for k in range(97)]
    test_perm(r5, f"R5-rotation-by-{C}")
except Exception:
    pass

print(f"  [R done]")

# ══════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("FINAL SUMMARY")
print("="*70)
print(f"Total permutations tested: {tested}")
print(f"Best score seen: {best_score_seen:.4f}/char")
print(f"Crib hits: {len(hits)}")
if hits:
    for h in hits:
        print(f"  *** HIT: {h['label']}")
        print(f"      PT: {h['pt']}")
        print(f"      Score: {h['score']:.4f}, ENE@{h['ene']}, BC@{h['bc']}")
else:
    print("  No crib hits found.")

# Save results
import json as json2
with open(f"{RESULTS_DIR}/results.json", 'w') as f:
    json2.dump({
        "tested": tested,
        "best_score": best_score_seen,
        "crib_hits": hits,
        "n_holes": len(holes),
        "forced_sigma_29": forced_sigma_29,
    }, f, indent=2)
print(f"\nResults saved to {RESULTS_DIR}/results.json")
