#!/usr/bin/env python3
"""
E-UNSCRAMBLE-01: Comprehensive grille-based unscrambling permutation search.

Paradigm: carved K4 = SCRAMBLE(real_CT). Grille defines the unscrambling permutation.
Find permutation σ such that σ(carved_K4) = real_CT, then decrypt real_CT.

Approaches:
  1.  Rank-perm from extract[0:97] in KA order
  2.  Rank-perm from extract[0:97] in AZ order
  3.  KA-position mod 97 → permutation
  4.  Extract-keyed columnar transpositions (W=5..24)
  5.  Physical reading orders (boustrophedon, column-major, diagonal)
  6.  Spiral reading orders
  7.  Grille overlay: K4 in W-wide grid, holes → reading order
  8.  T-position columnar transposition
  9.  Direct test: first 97 of extract AS real CT
 10.  Extract[0:97] letters pair with CT → positional map
 11.  Hole-position flat indices mod 97 → permutation
 12.  Reverse/mirror/interleave K4 variants
 13.  Extract sub-selections (every 2nd, skip first N)
 14.  Ranked hole column indices → transposition
 15.  Extract differential: (extract_pos[i] - ct_pos[i]) mod 26 → positions
"""

import sys, json, math, os, itertools
from collections import defaultdict

sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT

assert len(CT) == 97, f"Expected 97, got {len(CT)}"

GRILLE_EXTRACT = 'HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD'
assert len(GRILLE_EXTRACT) == 106

KA  = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
AZ  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
assert len(KA) == 26

CRIB1 = 'EASTNORTHEAST'   # length 13
CRIB2 = 'BERLINCLOCK'     # length 11
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'BERLIN', 'CLOCK',
            'NORTH', 'EAST', 'LAYER', 'ILLUSION', 'IQLUSION']

# ── Quadgram scorer ──────────────────────────────────────────────────────────
_QUAD, _FLOOR = None, None
def load_quads():
    global _QUAD, _FLOOR
    if _QUAD is not None:
        return
    data = json.load(open('data/english_quadgrams.json'))
    # Values are already log10 probabilities
    _QUAD  = data
    _FLOOR = min(data.values()) - 1.0

def quad_score(text):
    load_quads()
    s = 0.0
    for i in range(len(text) - 3):
        s += _QUAD.get(text[i:i+4], _FLOOR)
    return s / max(len(text) - 3, 1)

# ── Cipher engines ───────────────────────────────────────────────────────────
def _prep_key(key, alpha):
    return [alpha.index(k) for k in key if k in alpha]

def vigenere_dec(ct, key, alpha=AZ):
    kv = _prep_key(key, alpha); n = len(alpha)
    if not kv: return ''
    out = []
    ki = 0
    for c in ct:
        if c in alpha:
            out.append(alpha[(alpha.index(c) - kv[ki % len(kv)]) % n]); ki += 1
        else: out.append(c)
    return ''.join(out)

def beaufort_dec(ct, key, alpha=AZ):
    kv = _prep_key(key, alpha); n = len(alpha)
    if not kv: return ''
    out = []
    ki = 0
    for c in ct:
        if c in alpha:
            out.append(alpha[(kv[ki % len(kv)] - alpha.index(c)) % n]); ki += 1
        else: out.append(c)
    return ''.join(out)

def variant_beau_dec(ct, key, alpha=AZ):
    """Variant Beaufort: pt = ct XOR key (same as Vigenère encrypt with key)"""
    kv = _prep_key(key, alpha); n = len(alpha)
    if not kv: return ''
    out = []
    ki = 0
    for c in ct:
        if c in alpha:
            out.append(alpha[(alpha.index(c) + kv[ki % len(kv)]) % n]); ki += 1
        else: out.append(c)
    return ''.join(out)

# ── Permutation helpers ──────────────────────────────────────────────────────
def apply_perm(seq, perm):
    """Read seq in the order given by perm: result[i] = seq[perm[i]]"""
    return ''.join(seq[perm[i]] for i in range(len(perm)))

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, v in enumerate(perm): inv[v] = i
    return inv

def rank_perm(values):
    """Return indices sorted by values (stable). Gives permutation of 0..n-1."""
    return sorted(range(len(values)), key=lambda i: values[i])

# ── Crib & decryption sweep ──────────────────────────────────────────────────
all_results = []

def try_decrypt(label, candidate_ct, perm=None):
    """Try all keyword × cipher × alphabet combos on candidate_ct.
    Returns best (score, keyword, cipher, alpha, pt) and records CRIB HITS."""
    best = (-999.0, None, None, None, '')
    for kw in KEYWORDS:
        for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
            for fname, fn in [('vig', vigenere_dec), ('beau', beaufort_dec), ('vbeau', variant_beau_dec)]:
                pt = fn(candidate_ct, kw, alpha)
                if not pt: continue
                sc = quad_score(pt)
                has1 = CRIB1 in pt
                has2 = CRIB2 in pt
                entry = {
                    'label': label,
                    'keyword': kw,
                    'cipher': fname,
                    'alpha': alpha_name,
                    'ct': candidate_ct,
                    'pt': pt,
                    'score': round(sc, 5),
                    'has_crib1': has1,
                    'has_crib2': has2,
                    'CRIB_HIT': has1 or has2,
                }
                if has1 or has2:
                    all_results.append(entry)
                    print(f"  *** CRIB HIT *** {label} | {kw}/{fname}/{alpha_name}")
                    print(f"      PT: {pt}")
                if sc > best[0]:
                    best = (sc, kw, fname, alpha_name, pt)
    return best

def register(label, candidate_ct, perm=None):
    """Register a candidate unscrambled CT: try decryption, track top score."""
    sc, kw, fname, aname, pt = try_decrypt(label, candidate_ct, perm)
    top_scores.append((sc, label, candidate_ct, kw, fname, aname, pt))

top_scores = []

# ── Binary mask ──────────────────────────────────────────────────────────────
MASK_RAW = [
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

# Parse mask into (row, col, cell_value) lists
mask_cells = []   # all on-grid cells
holes = []        # on-grid cells with value 0
for r, row_str in enumerate(MASK_RAW):
    for c, ch in enumerate(row_str):
        if ch == '~': continue
        mask_cells.append((r, c, int(ch)))
        if ch == '0':
            holes.append((r, c))

print(f"Mask: {len(mask_cells)} on-grid cells, {len(holes)} holes (0s)")
print(f"K4 CT ({len(CT)}): {CT}")
print(f"Extract ({len(GRILLE_EXTRACT)}): {GRILLE_EXTRACT[:50]}...")

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 1 & 2: Rank-permutation from first 97 extract chars
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 1-2: Rank perm from extract[0:97] ──")
e97 = GRILLE_EXTRACT[:97]

for alpha_name, alpha in [('KA', KA), ('AZ', AZ)]:
    ka_vals = [alpha.index(c) if c in alpha else 99 for c in e97]
    perm = rank_perm(ka_vals)   # perm[i] = which extract position has i-th smallest value
    # result[i] = CT[perm[i]]  →  read CT in the order given by perm
    unsc = apply_perm(CT, perm)
    register(f'rank_extract97_{alpha_name}_fwd', unsc, perm)

    inv = invert_perm(perm)
    unsc_inv = apply_perm(CT, inv)
    register(f'rank_extract97_{alpha_name}_inv', unsc_inv, inv)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 3: KA-position mod 97 → permutation (first-occurrence)
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 3: KA-pos mod 97 first-occurrence ──")
for alpha_name, alpha in [('KA', KA), ('AZ', AZ)]:
    vals = [(alpha.index(c) if c in alpha else 99) % 97 for c in GRILLE_EXTRACT]
    seen = set(); perm = []
    for v in vals:
        if v not in seen: seen.add(v); perm.append(v)
        if len(perm) == 97: break
    if len(perm) == 97:
        unsc = apply_perm(CT, perm)
        register(f'kamod97_{alpha_name}_fwd', unsc, perm)
        unsc_inv = apply_perm(CT, invert_perm(perm))
        register(f'kamod97_{alpha_name}_inv', unsc_inv, invert_perm(perm))

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 4: Extract-keyed columnar transposition (widths 5–24)
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 4: Extract-keyed columnar transposition (W=5..24) ──")
hits_4 = 0
for W in range(5, 25):
    key = GRILLE_EXTRACT[:W]
    # Sort columns by AZ-rank of key letter
    col_order = sorted(range(W), key=lambda i: AZ.index(key[i]) if key[i] in AZ else 99)

    # Lay CT in rows of W
    n_rows = math.ceil(97 / W)
    # Forward: read columns in key-sorted order
    perm = []
    for c in col_order:
        for r in range(n_rows):
            idx = r * W + c
            if idx < 97: perm.append(idx)
    if len(perm) == 97 and len(set(perm)) == 97:
        unsc = apply_perm(CT, perm)
        register(f'ext_columnar_fwd_W{W}', unsc, perm)
        hits_4 += 1
        # Also try inverse (reverse read)
        inv = invert_perm(perm)
        unsc_inv = apply_perm(CT, inv)
        register(f'ext_columnar_inv_W{W}', unsc_inv, inv)

    # Also try with KA-ranking
    col_order_ka = sorted(range(W), key=lambda i: KA.index(key[i]) if key[i] in KA else 99)
    perm_ka = []
    for c in col_order_ka:
        for r in range(n_rows):
            idx = r * W + c
            if idx < 97: perm_ka.append(idx)
    if len(perm_ka) == 97 and len(set(perm_ka)) == 97:
        unsc = apply_perm(CT, perm_ka)
        register(f'ext_columnar_ka_W{W}', unsc, perm_ka)
        hits_4 += 1

print(f"  Tested {hits_4} valid columnar variants")

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 5: Physical reading orders
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 5: Physical reading orders ──")
hits_5 = 0
for W in [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20, 24, 25, 32, 33]:
    n_rows = math.ceil(97 / W)
    rows = [list(range(r*W, min((r+1)*W, 97))) for r in range(n_rows)]

    # 5a. Boustrophedon (alternating row direction)
    boustro = []
    for i, row in enumerate(rows):
        boustro.extend(reversed(row) if i % 2 else row)
    if len(boustro) == 97 and len(set(boustro)) == 97:
        register(f'boustro_W{W}', apply_perm(CT, boustro), boustro); hits_5 += 1

    # 5b. Column-major (top-to-bottom, left-to-right)
    colmaj = [r*W+c for c in range(W) for r in range(n_rows) if r*W+c < 97]
    if len(colmaj) == 97 and len(set(colmaj)) == 97:
        register(f'colmaj_W{W}', apply_perm(CT, colmaj), colmaj); hits_5 += 1

    # 5c. Column-major reversed (bottom-to-top)
    colmaj_rev = [r*W+c for c in range(W) for r in range(n_rows-1, -1, -1) if r*W+c < 97]
    if len(colmaj_rev) == 97 and len(set(colmaj_rev)) == 97:
        register(f'colmaj_rev_W{W}', apply_perm(CT, colmaj_rev), colmaj_rev); hits_5 += 1

    # 5d. Boustrophedon column-major (alternating column direction)
    boustro_cm = []
    for c in range(W):
        col_indices = [r*W+c for r in range(n_rows) if r*W+c < 97]
        if c % 2 == 1: col_indices = col_indices[::-1]
        boustro_cm.extend(col_indices)
    if len(boustro_cm) == 97 and len(set(boustro_cm)) == 97:
        register(f'boustro_cm_W{W}', apply_perm(CT, boustro_cm), boustro_cm); hits_5 += 1

print(f"  Tested {hits_5} valid reading-order variants")

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 6: Spiral reading orders
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 6: Spiral reading orders ──")
def spiral(n_rows, n_cols, n):
    indices = []
    top, bot, left, right = 0, n_rows-1, 0, n_cols-1
    while top <= bot and left <= right:
        for c in range(left, right+1):
            idx = top*n_cols + c
            if idx < n: indices.append(idx)
        top += 1
        for r in range(top, bot+1):
            idx = r*n_cols + right
            if idx < n: indices.append(idx)
        right -= 1
        if top <= bot:
            for c in range(right, left-1, -1):
                idx = bot*n_cols + c
                if idx < n: indices.append(idx)
            bot -= 1
        if left <= right:
            for r in range(bot, top-1, -1):
                idx = r*n_cols + left
                if idx < n: indices.append(idx)
            left += 1
    return indices

hits_6 = 0
for W in [7, 9, 10, 11, 12, 13, 14, 16, 17, 25, 33]:
    n_rows = math.ceil(97 / W)
    sp = spiral(n_rows, W, 97)
    if len(sp) == 97 and len(set(sp)) == 97:
        register(f'spiral_W{W}', apply_perm(CT, sp), sp); hits_6 += 1
    # Reversed spiral
    sp_rev = sp[::-1]
    if len(sp_rev) == 97 and len(set(sp_rev)) == 97:
        register(f'spiral_rev_W{W}', apply_perm(CT, sp_rev), sp_rev); hits_6 += 1

print(f"  Tested {hits_6} spiral variants")

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 7: Grille overlay — K4 in W-wide grid, holes → reading order
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 7: Grille overlay on K4 grid ──")
hits_7 = 0
for W in range(5, 34):
    grid = {}
    for idx in range(97):
        r = idx // W; c = idx % W
        grid[(r, c)] = idx
    selected = [grid[(r, c)] for (r, c) in holes if (r, c) in grid]
    if len(selected) == 97 and len(set(selected)) == 97:
        unsc = apply_perm(CT, selected)
        register(f'grille_overlay_W{W}', unsc, selected)
        hits_7 += 1
        print(f"    W={W}: valid permutation found via grille overlay!")
    elif 80 <= len(selected) < 97:
        pass  # partial hit, note but skip

print(f"  Tested W=5..33, found {hits_7} valid grille overlays")

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 8: T-position columnar transposition
# In KA tableau, row i starts at KA[i%26]. T is at KA-index 4.
# T appears in row i at column (4 - i) % 26 (0-indexed in 26-char block).
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 8: T-position columnar transposition ──")
t_cols_28 = [(4 - i) % 26 for i in range(28)]
print(f"  T-column positions (28 rows): {t_cols_28}")

# Use T-positions as ordering key for a columnar transposition on CT
# Layout CT in 28 columns
for W in [26, 28]:
    n_rows = math.ceil(97 / W)
    t_key = t_cols_28[:W]
    col_order = sorted(range(W), key=lambda c: t_key[c])
    perm = []
    for c in col_order:
        for r in range(n_rows):
            idx = r * W + c
            if idx < 97: perm.append(idx)
    if len(perm) == 97 and len(set(perm)) == 97:
        unsc = apply_perm(CT, perm)
        register(f't_col_columnar_W{W}', unsc, perm)
        unsc_inv = apply_perm(CT, invert_perm(perm))
        register(f't_col_columnar_inv_W{W}', unsc_inv, invert_perm(perm))

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 9: Direct — first 97 chars of extract AS real CT
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 9: Grille extract[0:97] as direct real CT ──")
e97_ct = GRILLE_EXTRACT[:97]
register('extract97_as_realCT', e97_ct)
# Also try last 97
register('extract_last97_as_realCT', GRILLE_EXTRACT[9:])
# Try all 97-char windows of the 106-char extract
for start in range(10):
    window = GRILLE_EXTRACT[start:start+97]
    if len(window) == 97:
        register(f'extract_window_{start}', window)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 10: Extract-CT pairing → positional map
# Pair (GRILLE_EXTRACT[i], CT[i]) for i=0..96
# The extract char's KA-position tells you the TARGET position in real CT
# real_CT[ka_pos(extract[i])] = CT[i]  (modulo collisions)
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 10: Extract-CT pairing → positional map ──")
for alpha_name, alpha in [('KA', KA), ('AZ', AZ)]:
    n = len(alpha)
    perm_map = {}  # target_pos → source_pos (last write wins)
    for i in range(97):
        c = GRILLE_EXTRACT[i]
        if c in alpha:
            target = alpha.index(c) % 97
        else:
            target = i % 97
        perm_map[target] = i

    if len(perm_map) == 97:
        perm = [perm_map[j] for j in range(97)]
        unsc = ''.join(CT[perm[j]] for j in range(97))
        register(f'extract_ct_pair_{alpha_name}', unsc, perm)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 11: Hole flat-index mod 97 → permutation
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 11: Hole flat-index mod 97 ──")
for row_width in [28, 33]:
    vals = [(r * row_width + c) % 97 for (r, c) in holes]
    seen = set(); perm = []
    for v in vals:
        if v not in seen: seen.add(v); perm.append(v)
        if len(perm) == 97: break
    if len(perm) == 97:
        unsc = apply_perm(CT, perm)
        register(f'hole_flatmod97_rw{row_width}_fwd', unsc, perm)
        unsc_inv = apply_perm(CT, invert_perm(perm))
        register(f'hole_flatmod97_rw{row_width}_inv', unsc_inv, invert_perm(perm))

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 12: Reverse/mirror/interleave K4 variants
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 12: Reverse/mirror/interleave K4 variants ──")
variants_12 = {
    'reversed': list(range(96, -1, -1)),
    'evens_then_odds': list(range(0, 97, 2)) + list(range(1, 97, 2)),
    'odds_then_evens': list(range(1, 97, 2)) + list(range(0, 97, 2)),
    'first_half_rev': list(range(48, -1, -1)) + list(range(49, 97)),
    'second_half_rev': list(range(0, 48)) + list(range(96, 47, -1)),
    'halves_swapped': list(range(49, 97)) + list(range(0, 49)),
    'thirds_rotated': list(range(33, 97)) + list(range(0, 33)),
    'thirds_rotated2': list(range(66, 97)) + list(range(0, 66)),
}
for name, perm in variants_12.items():
    if len(perm) == 97 and len(set(perm)) == 97:
        unsc = apply_perm(CT, perm)
        register(f'variant_{name}', unsc, perm)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 13: Extract sub-selections as rank keys
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 13: Extract sub-selections ──")
def rank_key_from_str(s97, alpha_name='KA'):
    alpha = KA if alpha_name == 'KA' else AZ
    vals = [alpha.index(c) if c in alpha else 99 for c in s97]
    return rank_perm(vals)

subsets = {
    'every_other_even': GRILLE_EXTRACT[0::2][:97] if len(GRILLE_EXTRACT[0::2]) >= 97 else None,
    'every_other_odd':  GRILLE_EXTRACT[1::2][:97] if len(GRILLE_EXTRACT[1::2]) >= 97 else None,
    'skip_first9':      GRILLE_EXTRACT[9:]  if len(GRILLE_EXTRACT[9:])  >= 97 else None,
    'take_first97':     GRILLE_EXTRACT[:97],
}
for sname, sval in subsets.items():
    if sval is None or len(sval) < 97: continue
    sval = sval[:97]
    for alpha_name in ['KA', 'AZ']:
        perm = rank_key_from_str(sval, alpha_name)
        unsc = apply_perm(CT, perm)
        register(f'subset_{sname}_rank_{alpha_name}', unsc, perm)
        inv = invert_perm(perm)
        register(f'subset_{sname}_rank_{alpha_name}_inv', apply_perm(CT, inv), inv)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 14: Ranked hole column indices → columnar transposition
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 14: Ranked hole-column indices as transposition key ──")
hole_cols = [c for (r, c) in holes]  # column index of each hole, in reading order
# For each width W, take first W hole-column values as the key
for W in range(5, 25):
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
        register(f'hole_col_trans_W{W}', unsc, perm)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 15: Extract-CT differential
# diff[i] = (extract_pos[i] - ct_pos[i]) mod 26  → mapped to 0..96
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 15: Extract-CT differential permutation ──")
for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
    n = len(alpha)
    diffs = []
    for i in range(97):
        e_pos = alpha.index(GRILLE_EXTRACT[i]) if GRILLE_EXTRACT[i] in alpha else 0
        c_pos = alpha.index(CT[i]) if CT[i] in alpha else 0
        diffs.append((e_pos - c_pos) % n)
    # Use diffs as ranking key
    perm = rank_perm(diffs)
    unsc = apply_perm(CT, perm)
    register(f'diff_perm_{alpha_name}_rank', unsc, perm)
    inv = invert_perm(perm)
    register(f'diff_perm_{alpha_name}_rank_inv', apply_perm(CT, inv), inv)
    # Also: use diff values directly as indices mod 97
    mod_vals = [d % 97 for d in diffs]
    seen = set(); perm2 = []
    for v in mod_vals:
        if v not in seen: seen.add(v); perm2.append(v)
        if len(perm2) == 97: break
    if len(perm2) == 97:
        unsc2 = apply_perm(CT, perm2)
        register(f'diff_mod97_{alpha_name}_fwd', unsc2, perm2)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 16: Extract as VarBeau key → K4, check if result is PT directly
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 16: Extract as direct running-key cipher ──")
for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
    for fname, fn in [('vig', vigenere_dec), ('beau', beaufort_dec), ('vbeau', variant_beau_dec)]:
        pt = fn(CT, GRILLE_EXTRACT[:97], alpha)
        has1 = CRIB1 in pt; has2 = CRIB2 in pt
        sc = quad_score(pt)
        entry = {
            'label': f'extract_direct_{fname}_{alpha_name}',
            'keyword': 'EXTRACT', 'cipher': fname, 'alpha': alpha_name,
            'ct': CT, 'pt': pt, 'score': round(sc, 5),
            'has_crib1': has1, 'has_crib2': has2, 'CRIB_HIT': has1 or has2,
        }
        if has1 or has2:
            all_results.append(entry)
            print(f"  *** CRIB HIT via extract direct key *** {entry['label']}")
        top_scores.append((sc, entry['label'], CT, 'EXTRACT', fname, alpha_name, pt))

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 17: Grille hole ROWS as group-index → interleave groups
# Each hole row defines a "group" of K4 chars; read groups in row order
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 17: Hole-row grouped interleaving ──")
# Group holes by row: hole_rows[r] = list of (r,c) pairs in that row
hole_rows = defaultdict(list)
for r, c in holes:
    hole_rows[r].append((r, c))

# For each width W, map hole (r,c) → K4 position
for W in [9, 10, 11, 12, 13]:
    n_rows_k4 = math.ceil(97 / W)
    # Assign each hole to a K4 position if (r < n_rows_k4) and (c < W) and r*W+c < 97
    groups = defaultdict(list)
    for r, c in holes:
        k4_pos = r * W + c
        if k4_pos < 97:
            groups[r].append(k4_pos)
    # Read groups in row-order (by row index ascending)
    perm = []
    seen = set()
    for row_idx in sorted(groups.keys()):
        for pos in sorted(groups[row_idx]):  # within row, left-to-right
            if pos not in seen: seen.add(pos); perm.append(pos)
    # If we got < 97, add the missing ones at the end
    missing = [p for p in range(97) if p not in seen]
    perm.extend(missing)
    if len(perm) == 97 and len(set(perm)) == 97:
        unsc = apply_perm(CT, perm)
        register(f'hole_row_groups_W{W}', unsc, perm)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 18: Hole column sequence as a cipher alphabet substitution
# The 106 extracted letters define a 25-letter "alphabet" (no T)
# Build a mono-sub cipher mapping AZ → GRILLE_EXTRACT letters
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 18: Grille extract as substitution alphabet ──")
# Build mapping: AZ letter i → first occurrence of KA[i] in extract
# Use this as a cipher key
unique_extract = []
seen = set()
for c in GRILLE_EXTRACT:
    if c not in seen: seen.add(c); unique_extract.append(c)

# Map AZ positions to extract-alphabet positions
# For each CT char, find its position in the extract's alphabet and convert
for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
    # Build a 26-char key: for each alpha letter, find where it first appears in extract
    extract_sub = {}
    for i, c in enumerate(alpha):
        pos = GRILLE_EXTRACT.find(c)  # first occurrence in extract
        if pos >= 0:
            extract_sub[c] = pos  # use position as the "key value"
    # Use these positions to define a permutation of CT's 97 chars
    # Sort CT positions by extract_sub value of CT[i]
    ct_with_extract_rank = [(extract_sub.get(CT[i], 999), i) for i in range(97)]
    perm = [i for _, i in sorted(ct_with_extract_rank)]
    unsc = apply_perm(CT, perm)
    register(f'extract_sub_perm_{alpha_name}', unsc, perm)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 19: Segment-reversal permutations
# Reverse specific segments of K4 (similar to strip cipher idea)
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 19: Segment-reversal permutations ──")
def seg_reverse(n, segments):
    """Reverse specified [start, end) segments of 0..n-1"""
    perm = list(range(n))
    for s, e in segments:
        perm[s:e] = perm[s:e][::-1]
    return perm

# Try reversing each "row" for various widths
for W in [9, 10, 11, 12, 13, 14, 17, 24, 33]:
    n_rows = math.ceil(97 / W)
    # Reverse every other row
    segs = [(r*W, min((r+1)*W, 97)) for r in range(0, n_rows, 2)]
    perm = seg_reverse(97, segs)
    if len(set(perm)) == 97:
        unsc = apply_perm(CT, perm)
        register(f'seg_rev_odd_rows_W{W}', unsc, perm)
    # Reverse ALL rows
    segs_all = [(r*W, min((r+1)*W, 97)) for r in range(n_rows)]
    perm_all = seg_reverse(97, segs_all)
    if len(set(perm_all)) == 97:
        unsc = apply_perm(CT, perm_all)
        register(f'seg_rev_all_rows_W{W}', unsc, perm_all)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 20: Grille-row hole counts as columnar transposition key
# Each row of the mask has a different number of holes → use count per row as key
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 20: Hole-count per row as columnar key ──")
hole_count_per_row = defaultdict(int)
for r, c in holes:
    hole_count_per_row[r] += 1

counts = [hole_count_per_row.get(r, 0) for r in range(28)]
print(f"  Hole counts per row (28 rows): {counts}")

# Use as key for 28-wide columnar transposition
W = 28
n_rows_ct = math.ceil(97 / W)
col_order = sorted(range(W), key=lambda c: counts[c])
perm = []
for c in col_order:
    for r in range(n_rows_ct):
        idx = r * W + c
        if idx < 97: perm.append(idx)
if len(perm) == 97 and len(set(perm)) == 97:
    unsc = apply_perm(CT, perm)
    register('hole_count_columnar_W28', unsc, perm)

# Also try with the 26-letter KA key width
W = 26
col_order_26 = sorted(range(W), key=lambda c: counts[c] if c < len(counts) else 0)
n_rows_ct = math.ceil(97 / W)
perm_26 = []
for c in col_order_26:
    for r in range(n_rows_ct):
        idx = r * W + c
        if idx < 97: perm_26.append(idx)
if len(perm_26) == 97 and len(set(perm_26)) == 97:
    unsc = apply_perm(CT, perm_26)
    register('hole_count_columnar_W26', unsc, perm_26)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 21: Alphabetically-sorted grille extract positions define K4 read order
# Sort extract characters alphabetically; the resulting index sequence IS the permutation
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 21: Alphabetical sort of full 106-char extract ──")
# Sort all 106 positions by letter value, take first 97 unique K4 positions
# Interpretation: position i in the SORTED list is where K4 char goes in real CT
for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
    sorted_106 = sorted(range(106), key=lambda i: alpha.index(GRILLE_EXTRACT[i]) if GRILLE_EXTRACT[i] in alpha else 99)
    # Map each sorted index to a K4 position (mod 97)
    seen = set(); perm = []
    for idx in sorted_106:
        k4_pos = idx % 97
        if k4_pos not in seen: seen.add(k4_pos); perm.append(k4_pos)
        if len(perm) == 97: break
    if len(perm) == 97:
        unsc = apply_perm(CT, perm)
        register(f'alpha_sort_106_{alpha_name}', unsc, perm)
        inv = invert_perm(perm)
        register(f'alpha_sort_106_{alpha_name}_inv', apply_perm(CT, inv), inv)

# ════════════════════════════════════════════════════════════════════════════
# APPROACH 22: K4 laid out at ACTUAL physical Kryptos plate positions
# Known: the Kryptos cipher section has rows of approximately 25 chars
# Try W = 25 with known physical row breaks
# ════════════════════════════════════════════════════════════════════════════
print("\n── APPROACH 22: Physical plate row-break variants ──")
# From research: Kryptos cipher plate likely has rows of ~25 chars
# K4 section row widths (hypothetical based on visual analysis):
# Various plausible K4 row-width combinations summing to 97
physical_configs = [
    # (label, list of row_lengths)
    ('row8x12_r1', [12, 12, 12, 12, 12, 12, 12, 11]),  # 8 rows
    ('row8_13_12', [13, 12, 12, 12, 12, 12, 12, 12]),
    ('row7_14', [14, 14, 14, 14, 14, 14, 13]),
    ('row6_17', [17, 17, 17, 17, 16, 13]),
    ('row5_20', [20, 20, 20, 20, 17]),
    ('row4_25', [25, 25, 25, 22]),
    ('row11_9', [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 7]),
    ('row10_10', [10, 10, 10, 10, 10, 10, 10, 10, 10, 7]),
    ('row8_12_11_alt', [12, 11, 12, 11, 12, 11, 12, 16]),  # variable
]

for label, row_lens in physical_configs:
    if sum(row_lens) != 97: continue
    # Build row→position mapping
    pos = 0
    row_positions = []
    for rlen in row_lens:
        row_positions.append(list(range(pos, pos + rlen)))
        pos += rlen

    # Boustrophedon on this layout
    boustro = []
    for i, row in enumerate(row_positions):
        boustro.extend(reversed(row) if i % 2 else row)
    if len(boustro) == 97 and len(set(boustro)) == 97:
        register(f'phys_boustro_{label}', apply_perm(CT, boustro), boustro)

    # Column-major on this layout (requires fixed-width)
    # Column-major only works nicely for uniform widths
    max_cols = max(row_lens)
    col_positions = defaultdict(list)
    pos = 0
    for rlen in row_lens:
        for j in range(rlen):
            col_positions[j].append(pos)
            pos += 1
    colmaj_phys = []
    for c in range(max_cols):
        colmaj_phys.extend(col_positions.get(c, []))
    if len(colmaj_phys) == 97 and len(set(colmaj_phys)) == 97:
        register(f'phys_colmaj_{label}', apply_perm(CT, colmaj_phys), colmaj_phys)

# ════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("RESULTS SUMMARY")
print("="*70)

# Sort by quadgram score
top_scores.sort(key=lambda x: x[0], reverse=True)

print(f"\nTotal candidate unscrambled CTs tested: {len(top_scores)}")
print(f"CRIB HITS (EASTNORTHEAST or BERLINCLOCK found): {len(all_results)}")

print("\nTop 20 by quadgram score:")
for i, (sc, label, ct, kw, fn, aname, pt) in enumerate(top_scores[:20]):
    has1 = CRIB1 in pt if pt else False
    has2 = CRIB2 in pt if pt else False
    crib_tag = " *** CRIB ***" if (has1 or has2) else ""
    print(f"  {i+1:2d}. {sc:7.4f}  {label:<50s} {kw}/{fn}/{aname}{crib_tag}")
    if pt: print(f"        PT: {pt[:60]}...")

if all_results:
    print(f"\n{'='*70}")
    print("CRIB HITS (FULL DETAILS):")
    for r in all_results:
        print(f"  Label: {r['label']}")
        print(f"  Key:   {r['keyword']}/{r['cipher']}/{r['alpha']}")
        print(f"  CT:    {r['ct']}")
        print(f"  PT:    {r['pt']}")
        print(f"  Score: {r['score']}")
        print()

# Save results
os.makedirs('kbot_results', exist_ok=True)
output = {
    'experiment': 'E-UNSCRAMBLE-01',
    'date': '2026-03-02',
    'paradigm': 'carved K4 = SCRAMBLE(real_CT); find unscrambling permutation',
    'total_candidates': len(top_scores),
    'total_hits': len(all_results),
    'any_crib_found': len(all_results) > 0,
    'crib_hits': all_results,
    'top_20': [
        {
            'rank': i+1,
            'score': round(sc, 5),
            'label': label,
            'candidate_ct': ct,
            'keyword': kw,
            'cipher': fn,
            'alpha': aname,
            'pt': pt,
            'has_crib1': (CRIB1 in pt) if pt else False,
            'has_crib2': (CRIB2 in pt) if pt else False,
        }
        for i, (sc, label, ct, kw, fn, aname, pt) in enumerate(top_scores[:20])
    ],
}
with open('kbot_results/unscramble_analysis.json', 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved → kbot_results/unscramble_analysis.json")
