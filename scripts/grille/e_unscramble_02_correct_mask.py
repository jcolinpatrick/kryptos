#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-UNSCRAMBLE-02: Corrected mask (107 holes) + new targeted approaches.

Key fix from E-UNSCRAMBLE-01:
  - Mask had 791 holes (WRONG: used 0=hole from compact format)
  - Correct authoritative mask has 107 holes (0=hole in space-separated format)
  - 1s in compact = 0s in space-separated = actual holes

New approaches here:
  A. Grille overlay on K4 for all widths (correct holes)
  B. 107-hole reading order → 97 K4 positions (various selection rules)
  C. Hole-sequence used as columnar key
  D. Pair: hole (r,c) KA-letter → numeric → K4 position index
  E. Hole-row and hole-column sequences as separate keys
  F. Extract letter ORDER (not values) → permutation of K4
  G. K4 laid in 28-col grid + T-column transposition (correct)
  H. Extract index arithmetic: extract_pos[i] XOR ct_pos[i], sum, difference
  I. ABSCISSA as primary key + various permutations to find EASTNORTHEAST
  J. Brute over all 107-choose-97 subsets → which gives valid perm
"""

import sys, json, math, os
from collections import defaultdict

sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT

assert len(CT) == 97

GRILLE_EXTRACT = 'HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD'
assert len(GRILLE_EXTRACT) == 106

KA  = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
AZ  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
CRIB1 = 'EASTNORTHEAST'
CRIB2 = 'BERLINCLOCK'
KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','BERLIN','CLOCK',
            'NORTH','EAST','LAYER','IQLUSION','ILLUSION']

# ── Authoritative mask (space-separated, 0=hole/visible, 1=masked) ────────
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

# Parse: 0=hole, 1=masked, ~=off-grid
mask_rows_parsed = []
HOLES = []  # (row, col) 0-indexed, reading order (row-major)
for r, line in enumerate(MASK_TEXT.strip().split('\n')):
    vals = line.split()
    row_data = []
    for c, v in enumerate(vals):
        if v == '~': row_data.append('~'); continue
        row_data.append(int(v))
        if v == '0':
            HOLES.append((r, c))
    mask_rows_parsed.append(row_data)

assert len(HOLES) == 107, f"Expected 107 holes, got {len(HOLES)}"
print(f"Mask: 107 holes confirmed, {len(mask_rows_parsed)} rows")

# ── KA Tableau (for extract letter lookup) ────────────────────────────────
TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",  # Row 15: N, 32 chars (extra L)
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWXT",  # Row 23: V, 32 chars (extra T)
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
]

# Verify extract by reading tableau at hole positions
extracted = []
for (r, c) in HOLES:
    if r < len(TABLEAU_ROWS):
        row_str = TABLEAU_ROWS[r]
        if c < len(row_str) and row_str[c] not in (' ', '~'):
            extracted.append(row_str[c])
print(f"Extracted from tableau at holes: {''.join(extracted[:50])}... (len={len(extracted)})")
print(f"Known extract (first 50): {GRILLE_EXTRACT[:50]}")

# ── Quadgrams ─────────────────────────────────────────────────────────────
_QUAD = json.load(open('data/english_quadgrams.json'))
_FLOOR = min(_QUAD.values()) - 1.0
def quad_score(text):
    s = sum(_QUAD.get(text[i:i+4], _FLOOR) for i in range(len(text)-3))
    return s / max(len(text)-3, 1)

# ── Cipher engines ────────────────────────────────────────────────────────
def _kv(key, alpha):
    return [alpha.index(k) for k in key if k in alpha]

def vig(ct, key, alpha=AZ):
    kv = _kv(key, alpha); n = len(alpha)
    if not kv: return ''
    out=[]; ki=0
    for c in ct:
        if c in alpha: out.append(alpha[(alpha.index(c)-kv[ki%len(kv)])%n]); ki+=1
        else: out.append(c)
    return ''.join(out)

def beau(ct, key, alpha=AZ):
    kv = _kv(key, alpha); n = len(alpha)
    if not kv: return ''
    out=[]; ki=0
    for c in ct:
        if c in alpha: out.append(alpha[(kv[ki%len(kv)]-alpha.index(c))%n]); ki+=1
        else: out.append(c)
    return ''.join(out)

def vbeau(ct, key, alpha=AZ):
    kv = _kv(key, alpha); n = len(alpha)
    if not kv: return ''
    out=[]; ki=0
    for c in ct:
        if c in alpha: out.append(alpha[(alpha.index(c)+kv[ki%len(kv)])%n]); ki+=1
        else: out.append(c)
    return ''.join(out)

def apply_perm(seq, perm):
    return ''.join(seq[perm[i]] for i in range(len(perm)))

def invert_perm(perm):
    inv=[0]*len(perm)
    for i,v in enumerate(perm): inv[v]=i
    return inv

def rank_perm(vals):
    return sorted(range(len(vals)), key=lambda i: vals[i])

# ── Scoring & result tracking ──────────────────────────────────────────────
all_crib_hits = []
top_scores = []

def sweep(label, candidate_ct, perm=None):
    """Try all keyword × cipher × alphabet combos."""
    best = (-999.0, None, None, None, '')
    for kw in KEYWORDS:
        for aname, alpha in [('AZ', AZ), ('KA', KA)]:
            for fname, fn in [('vig', vig), ('beau', beau), ('vbeau', vbeau)]:
                pt = fn(candidate_ct, kw, alpha)
                if not pt: continue
                sc = quad_score(pt)
                has1 = CRIB1 in pt; has2 = CRIB2 in pt
                if has1 or has2:
                    entry = {'label': label, 'kw': kw, 'cipher': fname,
                             'alpha': aname, 'ct': candidate_ct, 'pt': pt,
                             'score': round(sc,5), 'has1': has1, 'has2': has2}
                    all_crib_hits.append(entry)
                    print(f"  *** CRIB HIT *** {label} | {kw}/{fname}/{aname}")
                    print(f"      CT: {candidate_ct}")
                    print(f"      PT: {pt}")
                if sc > best[0]: best = (sc, kw, fname, aname, pt)
    top_scores.append((best[0], label, candidate_ct,
                       best[1], best[2], best[3], best[4]))
    return best

# ════════════════════════════════════════════════════════════════════════════
# APPROACH A: Grille overlay on K4 grid (CORRECTED — 107 holes)
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH A: Grille overlay on K4 grid (107 holes) ──")
found_A = 0
for W in range(5, 40):
    # Map each hole to a K4 position
    selected = []
    for (r, c) in HOLES:
        k4_pos = r * W + c
        if k4_pos < 97:
            selected.append(k4_pos)
    n_sel = len(selected)
    n_unique = len(set(selected))
    if n_unique == 97 and n_sel == 97:
        unsc = apply_perm(CT, selected)
        sweep(f'grille_overlay_W{W}', unsc, selected)
        found_A += 1
        print(f"  W={W}: valid permutation! {n_sel} positions selected")
    elif n_unique == 97 and n_sel > 97:
        # More than 97 selected but all unique — doesn't happen if grid is contiguous
        pass
    elif 90 <= n_sel <= 107 and n_unique >= 90:
        print(f"  W={W}: {n_sel} selected, {n_unique} unique (partial coverage)")
print(f"  Found {found_A} valid grille overlays")

# ════════════════════════════════════════════════════════════════════════════
# APPROACH B: 107-hole sequence → 97 K4 positions
# Treat holes as a sequence of 107 values; select 97 using various rules
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH B: 107-hole sequence → 97 K4 positions ──")

# B1: Hole flat indices mod 97 (first-occurrence)
for row_width in [28, 29, 30, 31, 32, 33]:
    vals = [(r * row_width + c) % 97 for (r, c) in HOLES]
    seen = set(); perm = []
    for v in vals:
        if v not in seen: seen.add(v); perm.append(v)
        if len(perm) == 97: break
    if len(perm) == 97:
        unsc = apply_perm(CT, perm)
        sweep(f'hole_flatmod97_rw{row_width}_fwd', unsc, perm)
        inv = invert_perm(perm)
        sweep(f'hole_flatmod97_rw{row_width}_inv', apply_perm(CT, inv), inv)

# B2: Hole row * 28 + col_within_alphabet (restrict to cols 1-26 = alpha cols)
# Tableau col 0 = row label, cols 1-26 = KA alphabet
alpha_holes = [(r, c-1) for (r, c) in HOLES if 1 <= c <= 26]
print(f"  Holes in alphabet cols (1-26): {len(alpha_holes)}")
if len(alpha_holes) >= 97:
    # Use first 97
    perm_alpha = [(r * 26 + c) % 97 for (r, c) in alpha_holes[:97]]
    seen = set(); perm_a = []
    for v in perm_alpha:
        if v not in seen: seen.add(v); perm_a.append(v)
        if len(perm_a) == 97: break
    if len(perm_a) == 97:
        unsc = apply_perm(CT, perm_a)
        sweep('hole_alpha_cols_mod97', unsc, perm_a)

# B3: Holes sorted by column-major order (read columns left-to-right)
holes_colmaj = sorted(HOLES, key=lambda x: (x[1], x[0]))
holes_rowmaj = HOLES  # already row-major
for name, ordered_holes in [('col_major', holes_colmaj), ('row_major', holes_rowmaj)]:
    for W in [26, 28, 33]:
        vals = [(r * W + c) % 97 for (r, c) in ordered_holes]
        seen = set(); perm = []
        for v in vals:
            if v not in seen: seen.add(v); perm.append(v)
            if len(perm) == 97: break
        if len(perm) == 97:
            unsc = apply_perm(CT, perm)
            sweep(f'hole_{name}_mod97_W{W}', unsc, perm)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH C: Hole columns as columnar key
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH C: Hole columns as columnar transposition key ──")
hole_cols = [c for (r, c) in HOLES]  # 107 column indices

for W in range(5, 30):
    key_vals = hole_cols[:W]
    col_order = sorted(range(W), key=lambda i: key_vals[i])
    n_rows = math.ceil(97 / W)
    perm = []
    for c in col_order:
        for r in range(n_rows):
            idx = r * W + c
            if idx < 97: perm.append(idx)
    if len(perm) == 97 and len(set(perm)) == 97:
        unsc = apply_perm(CT, perm)
        sweep(f'holecol_trans_W{W}', unsc, perm)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH D: Hole letter → KA position → K4 index
# Each hole at (r,c) has a tableau letter. Use that letter's position in KA
# as a seed for a K4 index.
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH D: Hole tableau-letter → KA index → K4 position ──")
hole_letters = []
for (r, c) in HOLES:
    if r < len(TABLEAU_ROWS):
        row_str = TABLEAU_ROWS[r]
        if c < len(row_str) and row_str[c].isalpha():
            hole_letters.append(row_str[c])
        else:
            hole_letters.append('?')
    else:
        hole_letters.append('?')
# Remove '?'
valid_hole_letters = [(i, l) for i, l in enumerate(hole_letters) if l != '?']
print(f"  Valid hole letters: {len(valid_hole_letters)}")
print(f"  First 20: {''.join(l for _,l in valid_hole_letters[:20])}")
print(f"  Matches extract: {''.join(l for _,l in valid_hole_letters[:20])} == {GRILLE_EXTRACT[:20]}? {all(l==GRILLE_EXTRACT[i] for i,l in enumerate([l for _,l in valid_hole_letters[:20]]))}")

# Use KA positions of hole letters as permutation keys
all_hole_letters_str = ''.join(l for _, l in valid_hole_letters)
if len(all_hole_letters_str) >= 97:
    e97 = all_hole_letters_str[:97]
    for alpha_name, alpha in [('KA', KA), ('AZ', AZ)]:
        vals = [alpha.index(c) if c in alpha else 99 for c in e97]
        perm = rank_perm(vals)
        unsc = apply_perm(CT, perm)
        sweep(f'hole_letter_rank_{alpha_name}', unsc, perm)
        inv = invert_perm(perm)
        sweep(f'hole_letter_rank_{alpha_name}_inv', apply_perm(CT, inv), inv)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH E: Hole row/col sequences as separate keys
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH E: Hole row and col sequences as keys ──")
hole_rows_seq = [r for (r, c) in HOLES]  # 107 row indices (0-27)
hole_cols_seq = [c for (r, c) in HOLES]  # 107 col indices (0-32)

for name, seq in [('row_seq', hole_rows_seq), ('col_seq', hole_cols_seq)]:
    # Use as rank key for K4
    seq97 = [v % 97 for v in seq[:97]]
    perm = rank_perm(seq97)
    unsc = apply_perm(CT, perm)
    sweep(f'hole_{name}_rank97', unsc, perm)

    # As columnar transposition key
    for W in [26, 28]:
        key_vals = seq[:W]
        col_order = sorted(range(W), key=lambda i: key_vals[i])
        n_rows = math.ceil(97 / W)
        perm2 = []
        for c in col_order:
            for rr in range(n_rows):
                idx = rr * W + c
                if idx < 97: perm2.append(idx)
        if len(perm2) == 97 and len(set(perm2)) == 97:
            unsc2 = apply_perm(CT, perm2)
            sweep(f'hole_{name}_columnar_W{W}', unsc2, perm2)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH F: Extract letter positions → permutation of K4
# Already done in E-UNSCRAMBLE-01, but with correct holes now confirm
# Extract letter at hole i corresponds to K4 position sigma(i)
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH F: Hole-sequence as K4 reading order (various mappings) ──")

# F1: Hole sequence rank = K4 reading order
# Read K4 in the order: first the chars that rank lowest in the hole-letter sequence
for alpha_name, alpha in [('KA', KA), ('AZ', AZ)]:
    if len(all_hole_letters_str) < 97: continue
    e97 = all_hole_letters_str[:97]
    # Stable sort by letter value; ties broken by position (= reading order)
    vals = [(alpha.index(c) if c in alpha else 99, i) for i, c in enumerate(e97)]
    perm = [i for (_, i) in sorted(vals)]
    unsc = apply_perm(CT, perm)
    sweep(f'hole_letter_stable_rank_{alpha_name}', unsc, perm)

# F2: Grille defines a one-time-pad: XOR K4 with extract (modular)
# Treat each K4 char and extract char as numbers in KA/AZ, XOR them
for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
    n = len(alpha)
    result = []
    for i in range(97):
        c_ct = alpha.index(CT[i]) if CT[i] in alpha else 0
        c_ex = alpha.index(GRILLE_EXTRACT[i]) if GRILLE_EXTRACT[i] in alpha else 0
        result.append(alpha[(c_ct ^ c_ex) % n])
    pt_xor = ''.join(result)
    has1 = CRIB1 in pt_xor; has2 = CRIB2 in pt_xor
    sc = quad_score(pt_xor)
    if has1 or has2:
        print(f"  *** XOR CRIB HIT *** {alpha_name}: {pt_xor}")
    top_scores.append((sc, f'xor_{alpha_name}', CT, 'XOR', 'xor', alpha_name, pt_xor))

# ════════════════════════════════════════════════════════════════════════════
# APPROACH G: Hole positions define GROUPS — each group = one "strip"
# K4 carved as strips, strips reordered by grille row order
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH G: Hole-row groupings as strip reordering ──")
# For each row of the mask with holes, those holes correspond to K4 strip positions
# The order in which rows appear with holes is the intended reading order of strips

# Find which rows have holes and how many
hole_row_counts = defaultdict(int)
for r, c in HOLES:
    hole_row_counts[r] += 1

# If K4 is divided into |mask_rows_with_holes| strips...
# For each divisor d of 97, split K4 into strips of size d or near-d
# and reorder strips by the grille's row order
rows_with_holes = sorted(hole_row_counts.keys())
n_strips = len(rows_with_holes)
print(f"  Rows with holes: {n_strips} rows ({rows_with_holes})")

# For strip sizes that divide near 97
for strip_size in range(1, 20):
    n_full = 97 // strip_size
    remainder = 97 % strip_size
    # Reorder K4 strips based on hole-row order
    # Only makes sense if n_full ≈ n_strips
    if abs(n_full - n_strips) <= 3:
        strips = []
        for s in range(n_full):
            strips.append(list(range(s*strip_size, (s+1)*strip_size)))
        if remainder:
            strips.append(list(range(n_full*strip_size, 97)))
        # Reorder by grille: use rows_with_holes as new strip order
        # rows_with_holes has n_strips elements; use them as permutation of strip indices
        if len(rows_with_holes) == len(strips):
            # Map: original_strip[i] goes to position rows_with_holes[i] in output
            # Or: reorder strips so that strip originally at rows_with_holes[i] comes first
            col_perm = sorted(range(len(strips)),
                              key=lambda i: rows_with_holes[i] if i < len(rows_with_holes) else 999)
            perm = []
            for si in col_perm:
                perm.extend(strips[si])
            if len(perm) == 97 and len(set(perm)) == 97:
                unsc = apply_perm(CT, perm)
                sweep(f'strip_grille_row_s{strip_size}', unsc, perm)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH H: Backsolve — what permutation makes ABSCISSA/KRYPTOS work?
# ABSCISSA decrypts ENE crib; KRYPTOS decrypts BC crib.
# If carved text[21:34] Vigenere(ABSCISSA) = EASTNORTHEAST,
# and carved text[63:74] Vigenere(KRYPTOS) = BERLINCLOCK,
# then at carved positions 21-33, ABSCISSA must decrypt the characters.
# Under the scrambled paradigm: carved[21:34] → after permutation → some position
# For ABSCISSA-Vig: carved[i] + ABSCISSA[key_pos] = PT[i] (this is already satisfied at pos 21-33)
# So the question is: what permutation gives us a FULL coherent PT?
#
# Insight: try all 97 starting offsets of the ABSCISSA key + look for ENE/BC anywhere
# This is the "crib drag" approach, but applied AFTER various permutations
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH H: Crib-drag for ABSCISSA/KRYPTOS on K4 variants ──")
# For each candidate permutation, apply ABSCISSA/KRYPTOS at all offsets
# (This is computationally feasible since we have ~300 candidates × 97 offsets × 2 keys)
# But actually we want to find WHICH permutation gives crib at EXPECTED position

# More targeted: if the permutation brings ENE to positions 21-33 in the unscrambled CT,
# and ABSCISSA is the key, then:
# real_CT[21:34] Vig_inv(ABSCISSA, real_CT[21:34]) = EASTNORTHEAST
# This means real_CT[21:34] is determined by ABSCISSA × EASTNORTHEAST
ALPHA = AZ
kw_abscissa = [ALPHA.index(k) for k in 'ABSCISSA']
kw_kryptos  = [ALPHA.index(k) for k in 'KRYPTOS']

ene_ct = ''.join(ALPHA[(ALPHA.index(CRIB1[i]) + kw_abscissa[i % len(kw_abscissa)]) % 26]
                 for i in range(len(CRIB1)))
bc_ct  = ''.join(ALPHA[(ALPHA.index(CRIB2[i]) + kw_kryptos[i % len(kw_kryptos)]) % 26]
                 for i in range(len(CRIB2)))
print(f"  ENE → CT under ABSCISSA-vig: {ene_ct}")
print(f"  BC  → CT under KRYPTOS-vig:  {bc_ct}")

# These are what the real CT should contain at the crib positions.
# Search for these sequences in the K4 carved text to find where they ARE.
for target, label in [(ene_ct, 'ENE_ct_ABSCISSA'), (bc_ct, 'BC_ct_KRYPTOS')]:
    pos = CT.find(target)
    if pos >= 0:
        print(f"  FOUND {label} at carved position {pos}: {CT[pos:pos+len(target)]}")
    else:
        # Check partial matches
        best_match = max(range(97-len(target)+1), key=lambda i: sum(CT[i+j]==target[j] for j in range(len(target))))
        n_match = sum(CT[best_match+j]==target[j] for j in range(len(target)))
        print(f"  {label} not found in K4. Best match {n_match}/{len(target)} at pos {best_match}")

# Also check BEAUFORT and VARIANT-BEAUFORT versions
for kw, kw_name in [('ABSCISSA', 'ABSCISSA'), ('KRYPTOS', 'KRYPTOS')]:
    for fname, fn in [('vig', vig), ('beau', beau), ('vbeau', vbeau)]:
        for aname, alpha in [('AZ', AZ), ('KA', KA)]:
            # Encrypt each crib
            crib_target = CRIB1 if kw_name == 'ABSCISSA' else CRIB2
            # "encrypt" crib to get expected CT sequence
            kv = [alpha.index(k) for k in kw if k in alpha]
            if not kv: continue
            if fname == 'vig':
                ct_seq = ''.join(alpha[(alpha.index(c)+kv[i%len(kv)])%len(alpha)]
                                 for i,c in enumerate(crib_target) if c in alpha)
            elif fname == 'beau':
                ct_seq = ''.join(alpha[(kv[i%len(kv)]+alpha.index(c))%len(alpha)]
                                 for i,c in enumerate(crib_target) if c in alpha)
            else:  # vbeau
                ct_seq = ''.join(alpha[(alpha.index(c)-kv[i%len(kv)])%len(alpha)]
                                 for i,c in enumerate(crib_target) if c in alpha)
            pos = CT.find(ct_seq)
            if pos >= 0:
                print(f"  FOUND expected CT for {kw_name}/{fname}/{aname} at carved pos {pos}: {ct_seq}")

# ════════════════════════════════════════════════════════════════════════════
# APPROACH I: Direct search — for each known keyword, apply at all positions
# and check if ANY permutation can place both cribs
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH I: Positional crib constraint solver ──")
# The key insight: under the SCRAMBLED model, the real CT contains the crib sequences.
# We know real CT is a permutation of carved K4.
# So: does K4 contain the characters of EASTNORTHEAST in some order?
# If we can find which 13 positions of K4 contain those characters (with the right key),
# those positions tell us where ENE is in the real CT.

# For ABSCISSA / Vigenère:
kw = 'ABSCISSA'; alpha = AZ
# ENE in PT means: real_CT[pos+i] = EASTNORTHEAST[i] ENCRYPTED by ABSCISSA[i%8]
# For a CYCLIC key ABSCISSA (len=8), the expected CT chars at position P are:
# CT[P+i] = (PT[i] + ABSCISSA[i%8]) mod 26

# Let's try: for each starting position P (0-96), compute expected real CT chars
# Then check if those chars (in that order) appear as a subsequence of K4 carved text
# This is harder than it sounds — we need them as consecutive positions in the real CT

# Simpler: check if the 13-char expected-CT for ENE is a SUBSTRING of K4
# (which means K4 contains ENE real-CT at some consecutive positions)
kv_ab = [AZ.index(k) for k in 'ABSCISSA']
for P in range(85):  # ENE length 13, so P can be 0..84
    expected_ct = ''.join(AZ[(AZ.index(CRIB1[i]) + kv_ab[i%8]) % 26]
                          for i in range(13))
    if expected_ct in CT:
        print(f"  ABSCISSA/vig: ENE expected CT '{expected_ct}' found at carved pos {CT.find(expected_ct)} (key offset P={P})")
    # Try Beaufort
    expected_ct_b = ''.join(AZ[(kv_ab[i%8] - AZ.index(CRIB1[i])) % 26]
                             for i in range(13))
    if expected_ct_b in CT:
        print(f"  ABSCISSA/beau: ENE expected CT '{expected_ct_b}' found at carved pos {CT.find(expected_ct_b)} (key offset P={P})")

# The key offset P matters when the key is not fixed-start
# For key offset P: ABSCISSA[P%8, (P+1)%8, ...]
for P in range(8):
    kv_ab_offset = [kv_ab[(P+i)%8] for i in range(13)]
    expected_ct = ''.join(AZ[(AZ.index(CRIB1[i]) + kv_ab_offset[i]) % 26]
                          for i in range(13))
    if expected_ct in CT:
        print(f"  ABSCISSA/vig offset {P}: ENE expected CT '{expected_ct}' FOUND AT CARVED POS {CT.find(expected_ct)}")
    expected_ct_b = ''.join(AZ[(kv_ab_offset[i] - AZ.index(CRIB1[i])) % 26]
                             for i in range(13))
    if expected_ct_b in CT:
        print(f"  ABSCISSA/beau offset {P}: BC expected CT '{expected_ct_b}' FOUND AT CARVED POS {CT.find(expected_ct_b)}")

kv_kr = [AZ.index(k) for k in 'KRYPTOS']
for P in range(7):
    kv_kr_offset = [kv_kr[(P+i)%7] for i in range(11)]
    expected_ct = ''.join(AZ[(AZ.index(CRIB2[i]) + kv_kr_offset[i]) % 26]
                          for i in range(11))
    if expected_ct in CT:
        print(f"  KRYPTOS/vig offset {P}: BC expected CT '{expected_ct}' FOUND AT CARVED POS {CT.find(expected_ct)}")

# ════════════════════════════════════════════════════════════════════════════
# APPROACH J: Structured permutations using hole geometry
# The 107 holes have a 2D structure. Their (row,col) pairs form a "point cloud".
# Use PCA-like ordering (project onto major axis) as permutation key.
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH J: Hole geometry — projected orderings ──")
# Project holes onto various directions
def project_and_rank(holes, angle_deg):
    """Rank holes by projection onto direction given by angle (degrees)."""
    import math
    th = math.radians(angle_deg)
    cos_t, sin_t = math.cos(th), math.sin(th)
    projs = [r * sin_t + c * cos_t for (r, c) in holes]
    return sorted(range(len(holes)), key=lambda i: projs[i])

for angle in [0, 30, 45, 60, 90, 120, 135, 150]:
    order = project_and_rank(HOLES, angle)
    # order[i] = which hole comes i-th when projected
    # Map the first 97 unique K4 positions
    vals = [(HOLES[i][0] * 33 + HOLES[i][1]) % 97 for i in order]
    seen = set(); perm = []
    for v in vals:
        if v not in seen: seen.add(v); perm.append(v)
        if len(perm) == 97: break
    if len(perm) == 97:
        unsc = apply_perm(CT, perm)
        sweep(f'hole_proj_angle{angle}', unsc, perm)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH K: The 106-char extract itself is the PT (not the CT)
# What if the extract IS the plaintext, and we need to find K4 = encrypt(PT)?
# Then: K4 carved text = SCRAMBLE(ENCRYPT(GRILLE_EXTRACT))
# To unscramble and decrypt: PT should be the 106-char extract (trimmed to 97)
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH K: Extract as PT — solve for key ──")
# If PT = GRILLE_EXTRACT[:97] and CT = K4 carved, what key does Vigenère need?
# Vig: CT[i] = (PT[i] + key[i%len]) mod 26
# key[i] = (CT[i] - PT[i]) mod 26
# This gives a running key; check if it has a pattern
for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
    n = len(alpha)
    pt97 = GRILLE_EXTRACT[:97]
    derived_key = []
    for i in range(97):
        if CT[i] in alpha and pt97[i] in alpha:
            k = (alpha.index(CT[i]) - alpha.index(pt97[i])) % n
            derived_key.append(alpha[k])
        else:
            derived_key.append('?')
    key_str = ''.join(derived_key)
    print(f"  Derived key ({alpha_name}): {key_str}")
    # Check for periodicity in derived key
    for period in range(1, 27):
        matches = sum(1 for i in range(97-period) if derived_key[i] == derived_key[i+period])
        if matches > 85:
            print(f"    Period {period}: {matches}/97 matches — strong periodicity!")

# ════════════════════════════════════════════════════════════════════════════
# APPROACH L: Columnar transposition using ABSCISSA / KRYPTOS as keywords
# These keywords encrypted K1 and K2 — maybe they ALSO define the K4 transposition
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH L: Known keyword columnar transpositions ──")
for kw in ['ABSCISSA', 'PALIMPSEST', 'KRYPTOS', 'SHADOW', 'BERLIN', 'EAST']:
    W = len(kw)
    for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
        col_order = sorted(range(W), key=lambda i: alpha.index(kw[i]) if kw[i] in alpha else 99)
        n_rows = math.ceil(97 / W)
        perm = []
        for c in col_order:
            for r in range(n_rows):
                idx = r * W + c
                if idx < 97: perm.append(idx)
        if len(perm) == 97 and len(set(perm)) == 97:
            unsc = apply_perm(CT, perm)
            sweep(f'kw_columnar_{kw}_{alpha_name}', unsc, perm)
            inv = invert_perm(perm)
            sweep(f'kw_columnar_{kw}_{alpha_name}_inv', apply_perm(CT, inv), inv)

# ════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
top_scores.sort(key=lambda x: x[0], reverse=True)
print(f"Candidates tested: {len(top_scores)}")
print(f"CRIB HITS: {len(all_crib_hits)}")
print("\nTop 20 by quadgram score:")
for i, (sc, label, ct, kw, fn, aname, pt) in enumerate(top_scores[:20]):
    crib_tag = " *** CRIB ***" if (CRIB1 in (pt or '') or CRIB2 in (pt or '')) else ""
    print(f"  {i+1:2d}. {sc:7.4f}  {label:<50s} {kw or '?'}/{fn or '?'}/{aname or '?'}{crib_tag}")
    if pt: print(f"        PT: {(pt or '')[:60]}...")

if all_crib_hits:
    print(f"\n{'='*70}\nCRIB HIT DETAILS:")
    for r in all_crib_hits:
        print(f"  {r['label']} | {r['kw']}/{r['cipher']}/{r['alpha']}")
        print(f"  CT: {r['ct']}")
        print(f"  PT: {r['pt']}")

os.makedirs('kbot_results', exist_ok=True)
with open('kbot_results/unscramble_analysis.json', 'w') as f:
    json.dump({
        'experiment': 'E-UNSCRAMBLE-02',
        'date': '2026-03-02',
        'total_candidates': len(top_scores),
        'total_hits': len(all_crib_hits),
        'any_crib_found': len(all_crib_hits) > 0,
        'crib_hits': all_crib_hits,
        'top_20': [{'rank': i+1, 'score': round(sc,5), 'label': label,
                    'ct': ct, 'kw': kw, 'cipher': fn, 'alpha': aname, 'pt': pt}
                   for i,(sc,label,ct,kw,fn,aname,pt) in enumerate(top_scores[:20])],
    }, f, indent=2)
print(f"\nResults saved → kbot_results/unscramble_analysis.json")
