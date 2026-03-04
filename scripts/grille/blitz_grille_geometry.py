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
Blitz Grille Geometry — comprehensive approach to Cardan grille permutation extraction.

Paradigm:
  PT → simple substitution → REAL CT → SCRAMBLE (transposition) → carved K4
  unscramble(K4) = real CT → Vig/Beau → PT  (must contain EASTNORTHEAST, BERLINCLOCK)

MASK: 1=hole (transparent), 0=masked/opaque, ~=off-grid (not part of tableau).
Off-grid cells at the END of each row are NOT holes (they're beyond the physical card).
"""

import json, sys, os, math
from collections import Counter

sys.path.insert(0, 'src')

# ─── Constants ────────────────────────────────────────────────────────────────
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GRILLE_EXTRACT) == 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
            'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA']

# ─── Binary Mask ──────────────────────────────────────────────────────────────
# Format: (data_string, num_offgrid_at_end)
# 1=hole, 0=masked. Off-grid cells at end are excluded.
# Row numbers are 0-indexed (row 0 = original "Row 01").
MASK_DATA = [
    ("000000001010100000000010000000001", 2),   # row 0:  valid cols 0-30, col 31-32 off-grid
    ("100000000010000001000100110000011", 2),   # row 1:  valid cols 0-30
    ("000000000000001000000000000000011", 2),   # row 2:  valid cols 0-30
    ("00000000000000000000100000010011",  2),   # row 3:  valid cols 0-29
    ("00000001000000001000010000000011",  2),   # row 4:  valid cols 0-29
    ("000000001000000000000000000000011", 1),   # row 5:  valid cols 0-31
    ("100000000000000000000000000000011", 0),   # row 6:  valid cols 0-32 (no off-grid)
    ("00000000000000000000000100000100",  2),   # row 7:  valid cols 0-29
    ("0000000000000000000100000001000",   2),   # row 8:  valid cols 0-28
    ("0000000000000000000000000000100",   2),   # row 9:  valid cols 0-28
    ("000000001000000000000000000000",    2),   # row 10: valid cols 0-27
    ("00000110000000000000000000000100",  2),   # row 11: valid cols 0-29
    ("00000000000000100010000000000001",  2),   # row 12: valid cols 0-29
    ("00000000000100000000000000001000",  2),   # row 13: valid cols 0-29
    ("000110100001000000000000001000010", 2),   # row 14: valid cols 0-30
    ("00001010000000000000000001000001",  2),   # row 15: valid cols 0-29
    ("001001000010010000000000000100010", 2),   # row 16: valid cols 0-30
    ("00000000000100000000010000010001",  2),   # row 17: valid cols 0-29
    ("000000000000010001001000000010001", 2),   # row 18: valid cols 0-30
    ("00000000000000001001000000000100",  2),   # row 19: valid cols 0-29
    ("000000001100000010100100010001001", 2),   # row 20: valid cols 0-30
    ("000000000000000100001010100100011", 1),   # row 21: valid cols 0-31
    ("00000000100000000000100001100001",  3),   # row 22: valid cols 0-28
    ("100000000000000000001000001000010", 1),   # row 23: valid cols 0-31
    ("10000001000001000000100000000001",  2),   # row 24: valid cols 0-29
    ("000010000000000000010000100000011", 0),   # row 25: valid cols 0-32 (no off-grid)
    ("000000000000000000010000100000011", 0),   # row 26: fixed (was 34 chars, truncated to 33)
    ("00000000000000100000001010000001",  2),   # row 27: valid cols 0-29
]
# Note: row 26 originally had "0000000000000000000100001000000011" (34 chars),
# corrected to 33 chars: "000000000000000000010000100000011"
# The holes at indices 31,32 in the original 34-char string become holes at 31,32 in 33-char string.

def parse_mask():
    """Parse mask data. Off-grid cells at end of each row are excluded."""
    holes = []
    for r, (data, n_offgrid) in enumerate(MASK_DATA):
        valid_len = len(data) - n_offgrid
        for c in range(valid_len):
            if c < len(data) and data[c] == '1':
                holes.append((r, c))
    return holes

HOLES = parse_mask()
print(f"Total holes (after off-grid exclusion): {len(HOLES)}")
print(f"Expected: ~107. Holes per row:")
hole_row_ct = Counter(r for r,c in HOLES)
for r in range(28):
    print(f"  Row {r:2d}: {hole_row_ct.get(r,0)} holes")
print(f"TOTAL: {sum(hole_row_ct.values())}")

# ─── Scoring ──────────────────────────────────────────────────────────────────
QG = json.load(open('data/english_quadgrams.json'))

def score_per_char(text):
    t = text.upper()
    n = len(t) - 3
    return (sum(QG.get(t[i:i+4], -10.0) for i in range(n)) / n) if n > 0 else -10.0

# ─── Cipher ops ───────────────────────────────────────────────────────────────
def vig_dec(ct, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(ct[i]) - alpha.index(key[i%len(key)])) % 26] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(key[i%len(key)]) - alpha.index(ct[i])) % 26] for i in range(len(ct)))

def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)

# ─── Results tracking ─────────────────────────────────────────────────────────
RESULTS_DIR = "blitz_results/grille_geometry"
os.makedirs(RESULTS_DIR, exist_ok=True)
all_results = []
crib_hits = []
tested = set()

def test_perm(perm, label):
    if label in tested:
        return None
    tested.add(label)
    perm = list(perm)
    if len(perm) != 97 or len(set(perm)) != 97 or min(perm) != 0 or max(perm) != 96:
        return None
    ct2 = apply_perm(K4, perm)
    best = None; best_sc = -1e9
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(ct2, kw, alpha)
                sc = score_per_char(pt)
                ene = pt.find("EASTNORTHEAST")
                bc  = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    r = {"label": label, "pt": pt, "score": sc, "key": kw,
                         "cipher": name, "alpha": alpha_name, "ene_pos": ene,
                         "bc_pos": bc, "perm": perm}
                    print(f"\n{'!'*60}")
                    print(f"*** CRIB HIT [{label}]  ENE@{ene}  BC@{bc}  key={kw}  {name}/{alpha_name}")
                    print(f"    PT: {pt}")
                    print(f"    Score: {sc:.4f}")
                    print('!'*60)
                    crib_hits.append(r); all_results.append(r)
                    return r
                if sc > best_sc:
                    best_sc = sc
                    best = {"label": label, "pt": pt, "score": sc, "key": kw,
                            "cipher": name, "alpha": alpha_name,
                            "ene_pos": ene, "bc_pos": bc}
    if best: all_results.append(best)
    return best

def report(label, perm):
    perm = list(perm)
    if len(perm) != 97 or len(set(perm)) != 97:
        return None
    r = test_perm(perm, label)
    if r:
        print(f"  [{label[:55]}] sc={r['score']:.4f} {r['key']:12s} {r['cipher']}/{r['alpha']}")
    return r

# ─── Derived orderings ────────────────────────────────────────────────────────
holes_rc   = sorted(HOLES, key=lambda h: (h[0], h[1]))
holes_cr   = sorted(HOLES, key=lambda h: (h[1], h[0]))
holes_diag = sorted(HOLES, key=lambda h: (h[0]+h[1], h[0]))
holes_anti = sorted(HOLES, key=lambda h: (h[0]-h[1], h[0]))
holes_flat = sorted(HOLES, key=lambda h: h[0]*34 + h[1])

# ─── Symmetry transforms ─────────────────────────────────────────────────────
def sort_rc(hs): return sorted(hs, key=lambda h: (h[0], h[1]))

NR, NC = 28, 33
transforms = {
    "id":       sort_rc(HOLES),
    "rot90":    sort_rc([(c, NR-1-r) for r,c in HOLES]),
    "rot180":   sort_rc([(NR-1-r, NC-1-c) for r,c in HOLES]),
    "rot270":   sort_rc([(NC-1-c, r) for r,c in HOLES]),
    "flipH":    sort_rc([(r, NC-1-c) for r,c in HOLES]),
    "flipV":    sort_rc([(NR-1-r, c) for r,c in HOLES]),
    "tr":       sort_rc([(c, r) for r,c in HOLES]),  # transpose
    "anti_tr":  sort_rc([(NC-1-c, NR-1-r) for r,c in HOLES]),
}

# ─── Utility functions ────────────────────────────────────────────────────────
def dedup_mod97(sequence, n=97):
    """Take first n unique values from sequence mod 97."""
    used = set(); out = []
    for v in sequence:
        v = v % n
        if v not in used:
            used.add(v); out.append(v)
        if len(out) == n: break
    return out if len(out) == n else None

def overlay_perm(hs, k4w, n=97):
    """K4 laid out in rows of k4w cols, holes (r,c) select K4[r*k4w+c]."""
    used = set(); out = []
    for r,c in hs:
        pos = r*k4w+c
        if 0 <= pos < n and pos not in used:
            used.add(pos); out.append(pos)
    return out if len(out) == n else None

def columnar_perm(key, n=97):
    """Keyword columnar: write n chars in len(key) cols, read in key-rank order."""
    nc = len(key); nr = math.ceil(n/nc)
    cols = sorted(range(nc), key=lambda i: (key[i], i))
    perm = []
    for c in cols:
        for r in range(nr):
            pos = r*nc+c
            if pos < n: perm.append(pos)
    return perm

def col_read_perm(width, n=97):
    """Write n chars in `width` cols, read column by column."""
    nr = math.ceil(n/width)
    perm = []
    for c in range(width):
        for r in range(nr):
            pos = r*width+c
            if pos < n: perm.append(pos)
    return perm

print(f"\nUsable holes: {len(HOLES)}")

# ═══════════════════════════════════════════════════════════════
# PART A: Direct hole coordinate → K4 index mappings
# ═══════════════════════════════════════════════════════════════
print("\n=== PART A: Hole coordinate mappings ===")

for tname, hs in transforms.items():
    for w in [29, 30, 31, 32, 33]:
        # A1: flat mod 97, dedup
        p = dedup_mod97((h[0]*w + h[1] for h in hs))
        if p: report(f"A1_{tname}_w{w}_flat_dedup", p)

        # A2: argsort of flat values (rank ordering)
        flat_vals = [h[0]*w + h[1] for h in hs[:97]]
        if len(flat_vals) >= 97:
            argsort = sorted(range(97), key=lambda i: (flat_vals[i], i))
            if len(set(argsort)) == 97:
                report(f"A2_{tname}_w{w}_argsort", argsort)

# A3: sort K4 positions by hole column
if len(holes_rc) >= 97:
    by_col = sorted(range(97), key=lambda i: (holes_rc[i][1], i))
    by_row = sorted(range(97), key=lambda i: (holes_rc[i][0], i))
    report("A3a_by_hole_col", by_col)
    report("A3b_by_hole_row", by_row)

# ═══════════════════════════════════════════════════════════════
# PART B: Overlay — K4 laid out in grid, holes select positions
# ═══════════════════════════════════════════════════════════════
print("\n=== PART B: Overlay K4 in grid ===")

for tname, hs in transforms.items():
    for k4w in range(29, 34):
        p = overlay_perm(hs, k4w)
        if p:
            report(f"B1_{tname}_k4w{k4w}", p)
            # Also inverse
            inv = [0]*97
            for i,v in enumerate(p): inv[v] = i
            report(f"B1_{tname}_k4w{k4w}_inv", inv)

# ═══════════════════════════════════════════════════════════════
# PART C: Rotation sequences (traditional Cardan 4-rotation)
# ═══════════════════════════════════════════════════════════════
print("\n=== PART C: 4-rotation Cardan sequence ===")

rot_seqs = {
    "0+90+180+270": (transforms["id"] + transforms["rot90"] +
                     transforms["rot180"] + transforms["rot270"]),
    "0+180+90+270": (transforms["id"] + transforms["rot180"] +
                     transforms["rot90"] + transforms["rot270"]),
    "0+flipH+180+flipV": (transforms["id"] + transforms["flipH"] +
                          transforms["rot180"] + transforms["flipV"]),
}
for sname, seq in rot_seqs.items():
    for w in [29, 30, 31, 32, 33]:
        p = dedup_mod97((h[0]*w + h[1] for h in seq))
        if p: report(f"C1_{sname}_w{w}", p)
    for k4w in range(29, 34):
        p = overlay_perm(seq, k4w)
        if p: report(f"C2_{sname}_k4w{k4w}", p)

# ═══════════════════════════════════════════════════════════════
# PART D: Row/column hole counts → columnar transposition key
# ═══════════════════════════════════════════════════════════════
print("\n=== PART D: Hole count keys ===")

row_ct = [hole_row_ct.get(r, 0) for r in range(28)]
col_ct_dict = Counter(c for r,c in HOLES)
col_ct = [col_ct_dict.get(c, 0) for c in range(34)]
print(f"  Row counts: {row_ct}")
print(f"  Col counts: {col_ct}")

for name, key in [("row", row_ct), ("col", col_ct),
                  ("row_nz", [c for c in row_ct if c>0]),
                  ("col_nz", [c for c in col_ct if c>0])]:
    p = columnar_perm(key)
    if len(p)==97 and len(set(p))==97:
        report(f"D1_{name}_columnar", p)
    # Also reversed key
    p2 = columnar_perm(list(reversed(key)))
    if len(p2)==97 and len(set(p2))==97:
        report(f"D1_{name}_rev_columnar", p2)

# Cumulative counts
cumul_row = []
acc = 0
for c in row_ct:
    acc += c; cumul_row.append(acc)
p = columnar_perm(cumul_row)
if len(p)==97 and len(set(p))==97: report("D2_cumul_row_columnar", p)

# ═══════════════════════════════════════════════════════════════
# PART E: Grille extract as permutation source
# ═══════════════════════════════════════════════════════════════
print("\n=== PART E: Grille extract permutations ===")

# E1: Argsort of grille extract
ge97 = GRILLE_EXTRACT[:97]
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    vals = [alpha.index(c) if c in alpha else 25 for c in ge97]
    argsort = sorted(range(97), key=lambda i: (vals[i], i))
    report(f"E1_ge97_argsort_{alpha_name}", argsort)
    inv = [0]*97
    for r,i in enumerate(argsort): inv[i] = r
    report(f"E1_ge97_rank_{alpha_name}", inv)

# E2: Argsort of all 106 grille chars, then first 97 unique mod 97
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    vals = [alpha.index(c) if c in alpha else 25 for c in GRILLE_EXTRACT]
    sorted_idx = sorted(range(106), key=lambda i: (vals[i], i))
    p = dedup_mod97(sorted_idx)
    if p: report(f"E2_ge106_argsort_mod97_{alpha_name}", p)

# E3: Grille extract as columnar keyword
for klen in [7, 9, 10, 11, 13, 14, 17, 19, 20, 24, 97]:
    kw = GRILLE_EXTRACT[:klen]
    p = columnar_perm(kw)
    if len(p)==97 and len(set(p))==97:
        report(f"E3_ge_col_key_len{klen}", p)

# E4: Grille extract as running key (direct Vigenère/Beaufort, no unscramble)
print("  E4: Grille extract as running key")
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
        pt = fn(K4, ge97, alpha)
        sc = score_per_char(pt)
        ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
        label = f"E4_ge_running_{name}_{alpha_name}"
        if ene >= 0 or bc >= 0:
            print(f"    *** CRIB HIT {label}: ENE@{ene} BC@{bc}")
        if label not in tested:
            tested.add(label)
            all_results.append({"label": label, "pt": pt, "score": sc, "key": "ge97",
                                 "cipher": name, "alpha": alpha_name, "ene_pos": ene, "bc_pos": bc})

# E5: Grille extract letter-frequency as columnar key
from collections import Counter as Ctr
freq97 = Ctr(ge97)
freq_key = [freq97.get(c, 0) for c in ge97]
p = columnar_perm(freq_key)
if len(p)==97 and len(set(p))==97: report("E5_ge_freq_columnar", p)

# E6: Substrings of 97 from grille extract (skip 9 from front/back/middle)
print("  E6: Grille 97-char substrings as running keys")
for start in range(0, 10):
    sub = GRILLE_EXTRACT[start:start+97]
    if len(sub) == 97:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(K4, sub, alpha)
                ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                label = f"E6_ge_skip{start}_{name}_{alpha_name}"
                if ene >= 0 or bc >= 0:
                    print(f"    *** CRIB HIT {label}: ENE@{ene} BC@{bc}")
                    print(f"    PT: {pt}")
                if label not in tested:
                    tested.add(label)
                    sc = score_per_char(pt)
                    all_results.append({"label": label, "pt": pt, "score": sc, "key": sub,
                                        "cipher": name, "alpha": alpha_name, "ene_pos": ene, "bc_pos": bc})

# ═══════════════════════════════════════════════════════════════
# PART F: Extended columnar widths
# ═══════════════════════════════════════════════════════════════
print("\n=== PART F: Columnar widths 11-97 ===")

for w in range(11, 97):
    p = col_read_perm(w)
    report(f"F1_col_w{w}", p)

# ═══════════════════════════════════════════════════════════════
# PART G: Stride / modular permutations (97 is prime)
# ═══════════════════════════════════════════════════════════════
print("\n=== PART G: Stride permutations (97 prime, all strides coprime) ===")

# Since 97 is prime, every stride 1..96 is coprime with 97
for stride in range(2, 97):
    p = [(i * stride) % 97 for i in range(97)]
    report(f"G1_stride{stride}", p)

# ═══════════════════════════════════════════════════════════════
# PART H: Hole flat positions as numeric permutation
# ═══════════════════════════════════════════════════════════════
print("\n=== PART H: Hole flat positions → permutation ===")

for tname, hs in transforms.items():
    flat_vals = [h[0]*33 + h[1] for h in hs]
    for n_skip in [0, 1, 2, 5, 8, 9, 10]:
        seq = flat_vals[n_skip:]
        p = dedup_mod97(seq)
        if p: report(f"H1_{tname}_skip{n_skip}_flat_dedup", p)

# Gaps between consecutive flat positions
flat_sorted = sorted([h[0]*33 + h[1] for h in HOLES])
gaps = [flat_sorted[i+1]-flat_sorted[i] for i in range(len(flat_sorted)-1)]
print(f"  Gaps (first 20): {gaps[:20]}")

p = dedup_mod97(gaps)
if p: report("H2_gaps_dedup", p)

# Cumulative gaps
acc = 0; cumul = []
for g in gaps:
    acc = (acc + g) % 97; cumul.append(acc)
p_c = list(dict.fromkeys(cumul))
if len(p_c) >= 97: report("H3_cumul_gaps", p_c[:97])

# ═══════════════════════════════════════════════════════════════
# PART I: K4 self-referential permutations
# ═══════════════════════════════════════════════════════════════
print("\n=== PART I: K4 self-referential ===")

for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    vals = [alpha.index(K4[i]) if K4[i] in alpha else 25 for i in range(97)]
    argsort = sorted(range(97), key=lambda i: (vals[i], i))
    report(f"I1_k4_argsort_{alpha_name}", argsort)
    inv = [0]*97
    for r,i in enumerate(argsort): inv[i] = r
    report(f"I1_k4_rank_{alpha_name}", inv)

# ═══════════════════════════════════════════════════════════════
# PART J: Diagonal and boustrophedon readings
# ═══════════════════════════════════════════════════════════════
print("\n=== PART J: Diagonal / boustrophedon orderings ===")

orderings = {
    "diag_NWSE":      sorted(HOLES, key=lambda h: (h[0]+h[1], h[0])),
    "diag_NESW":      sorted(HOLES, key=lambda h: (h[0]-h[1], h[0])),
    "diag_NWSE_rev":  sorted(HOLES, key=lambda h: (-(h[0]+h[1]), h[0])),
    "diag_NESW_rev":  sorted(HOLES, key=lambda h: (-(h[0]-h[1]), h[0])),
    "spiral_out":     sorted(HOLES, key=lambda h: (math.sqrt((h[0]-14)**2+(h[1]-16)**2), math.atan2(h[0]-14,h[1]-16))),
    "spiral_in":      sorted(HOLES, key=lambda h: (-math.sqrt((h[0]-14)**2+(h[1]-16)**2), math.atan2(h[0]-14,h[1]-16))),
}

# boustrophedon
by_row_d = {}
for r,c in HOLES: by_row_d.setdefault(r,[]).append(c)
bous = []
for r in sorted(by_row_d): cols = sorted(by_row_d[r]); bous += [(r,c) for c in (cols if r%2==0 else reversed(cols))]
orderings["boustrophedon"] = bous

for oname, hs in orderings.items():
    for k4w in range(29, 34):
        p = overlay_perm(hs, k4w)
        if p: report(f"J1_{oname}_k4w{k4w}", p)
    for w in [29, 30, 31, 32, 33]:
        p = dedup_mod97(h[0]*w+h[1] for h in hs)
        if p: report(f"J2_{oname}_w{w}_dedup", p)

# ═══════════════════════════════════════════════════════════════
# PART K: Double columnar transpositions
# ═══════════════════════════════════════════════════════════════
print("\n=== PART K: Double columnar transpositions ===")

def apply_col(text, width):
    n=len(text); nr=math.ceil(n/width)
    padded = text + 'X'*(nr*width-n)
    return ''.join(padded[r*width+c] for c in range(width) for r in range(nr))[:n]

for w1 in range(3, 14):
    for w2 in range(3, 14):
        if w1 == w2: continue
        ct2 = apply_col(apply_col(K4, w1), w2)
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for kw in KEYWORDS:
                for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                    pt = fn(ct2, kw, alpha)
                    ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                    if ene >= 0 or bc >= 0:
                        print(f"\n*** CRIB HIT K1(w1={w1},w2={w2}): ENE@{ene} BC@{bc} key={kw}")
                        print(f"    PT: {pt}")

# ═══════════════════════════════════════════════════════════════
# PART L: Grille extract letter indices → K4 position sequence
# ═══════════════════════════════════════════════════════════════
print("\n=== PART L: Grille extract → K4 position lookup ===")

# L1: For each grille extract letter, find positions of that letter in K4
# Build a mapping: letter → list of K4 positions with that letter
k4_letter_positions = {}
for i, ch in enumerate(K4):
    k4_letter_positions.setdefault(ch, []).append(i)

# Follow grille extract: for each letter, take the next unused K4 position of that letter
used_pos = set()
sequence_from_grille = []
position_queues = {ch: list(pos) for ch, pos in k4_letter_positions.items()}
for letter in GRILLE_EXTRACT:
    if letter in position_queues and position_queues[letter]:
        pos = position_queues[letter].pop(0)
        if pos not in used_pos:
            used_pos.add(pos)
            sequence_from_grille.append(pos)

print(f"  L1: Letters in grille extract found in K4: {len(sequence_from_grille)}")
if len(sequence_from_grille) >= 97:
    report("L1_grille_to_k4_letter_seq", sequence_from_grille[:97])

# L2: Grille extract as K4 READ-ORDER index sequence
# grille_extract[i] → index into K4 alphabet (AZ/KA)
# Use this as the KEY to re-order K4 positions
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    idx106 = [alpha.index(c) if c in alpha else 0 for c in GRILLE_EXTRACT]
    # Each value is 0-25. Map to K4 positions (blocks of 4): pos = idx * (97//26)
    # This is too coarse. Instead try: sequence of K4 positions guided by grille letter values

    # Approach: sort K4 positions 0..96 by their K4[i] value in the grille alphabet,
    # then use the grille extract letter VALUES as the secondary order
    positions = sorted(range(97), key=lambda i: (alpha.index(K4[i]) if K4[i] in alpha else 25, i))
    report(f"L2_k4_sorted_by_{alpha_name}", positions)

# ═══════════════════════════════════════════════════════════════
# PART M: Row-by-row hole patterns as AMSCO/periodic transpositions
# ═══════════════════════════════════════════════════════════════
print("\n=== PART M: Row hole patterns as AMSCO-style key ===")

# For AMSCO: hole counts per row define alternating 1/2 char groups
# Use hole_counts as the groups
hole_row_counts = [hole_row_ct.get(r, 0) for r in range(28)]

def amsco_perm(groups, n=97):
    """AMSCO transposition: groups define chars taken from each column per row.
    groups[col] = 1 or 2, alternating. Here we use hole counts."""
    # Standard AMSCO: fill text into cols, alternating 1 or 2 chars per cell
    if not groups: return None
    # Use groups as widths for each row assignment
    total = 0; row_assignments = []
    for g in groups:
        if g == 0: continue
        row_assignments.append((total, min(g, n-total)))
        total += g
        if total >= n: break
    # This doesn't directly give a standard permutation, skip
    return None

# Instead, use hole counts as a key for columnar transposition
# (already done in Part D)

# ═══════════════════════════════════════════════════════════════
# PART N: Grille + known keyword interactions
# ═══════════════════════════════════════════════════════════════
print("\n=== PART N: Keyword-guided permutations ===")

# N1: Use KRYPTOS/PALIMPSEST as columnar key, then apply grille extract as running key
for kw_col in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
    p = columnar_perm(kw_col)
    if len(p)==97 and len(set(p))==97:
        ct2 = apply_perm(K4, p)
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for sub_start in range(10):
                sub = GRILLE_EXTRACT[sub_start:sub_start+97]
                if len(sub) < 97: continue
                for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                    pt = fn(ct2, sub, alpha)
                    ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                    label = f"N1_{kw_col}_col_then_ge{sub_start}_{name}_{alpha_name}"
                    if ene >= 0 or bc >= 0:
                        print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
                        print(f"    PT: {pt}")
                    # Record best without crib
                    sc = score_per_char(pt)
                    if sc > -7.5 and label not in tested:
                        tested.add(label)
                        all_results.append({"label": label, "pt": pt, "score": sc,
                                            "key": kw_col, "cipher": name, "alpha": alpha_name,
                                            "ene_pos": ene, "bc_pos": bc})

# N2: Use known cribs as columnar keys
for crib in ["EASTNORTHEAST", "BERLINCLOCK"]:
    p = columnar_perm(crib)
    if len(p)==97 and len(set(p))==97:
        report(f"N2_{crib}_col_key", p)

# ═══════════════════════════════════════════════════════════════
# PART O: 97 as prime — generator-based permutations
# ═══════════════════════════════════════════════════════════════
print("\n=== PART O: Prime-field generators mod 97 ===")

# Powers of generators mod 97 (97 is prime)
# Find all primitive roots mod 97
# A primitive root g mod 97: g^k mod 97 generates all 1..96 for k=0..95
# then add 0 somewhere to complete 0..96

# Try all possible generators
def is_prim_root(g, p=97):
    seen = set()
    x = 1
    for _ in range(p-1):
        x = (x * g) % p
        if x in seen: return False
        seen.add(x)
    return len(seen) == p-1

prim_roots = [g for g in range(2, 97) if is_prim_root(g)]
print(f"  Primitive roots mod 97: {prim_roots}")

for g in prim_roots[:10]:  # test first 10 primitive roots
    # Generate sequence: g^0, g^1, g^2, ... mod 97 (gives 1..96, missing 0)
    seq = [pow(g, k, 97) for k in range(97)]  # includes g^0=1, wraps back to 1 at k=96
    # Make it 0..96: shift by 0 or use seq as ordering
    # Actually pow(g, k, 97) for k=0..95 gives all of 1..96; for k=96 it wraps to 1
    seq96 = [pow(g, k, 97) - 1 for k in range(97)]  # shifts 1..96 → 0..95, and 97-1=96 at k=96
    # Check if valid: seq96 = 0..95 repeated + 96? No...
    # Better: use sequence as SORT KEY
    sort_order = sorted(range(97), key=lambda i: (pow(g, i+1, 97) if i < 96 else 0))
    report(f"O1_primroot{g}_sortkey", sort_order)

# ═══════════════════════════════════════════════════════════════
# PART P: Inverse permutations of everything found so far
# ═══════════════════════════════════════════════════════════════
print("\n=== PART P: Inverse permutations ===")

snapshot = list(all_results)
for r in snapshot:
    if 'perm' not in r: continue
    p = r['perm']
    if len(p)!=97 or len(set(p))!=97: continue
    inv = [0]*97
    for i,v in enumerate(p): inv[v] = i
    report(f"P_inv_{r['label']}", inv)

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print(f"Total permutations tested: {len(tested)}")
print(f"Results recorded: {len(all_results)}")

if crib_hits:
    print(f"\n{'!'*60}\nCRIB HITS: {len(crib_hits)}")
    for h in crib_hits:
        print(f"  [{h['label']}]  ENE@{h['ene_pos']}  BC@{h['bc_pos']}")
        print(f"  PT: {h['pt']}\n  Score: {h['score']:.4f}")
else:
    print("\nNo crib hits found.")

# Top 20 by score
if all_results:
    top = sorted(all_results, key=lambda r: r['score'], reverse=True)[:20]
    print("\nTop 20 results by quadgram score:")
    for r in top:
        print(f"  [{r['label'][:50]:50s}] sc={r['score']:.4f} {r['key']:12s} {r['cipher']}/{r['alpha']}")
        print(f"    PT: {r['pt'][:70]}")

with open(f"{RESULTS_DIR}/results.json", 'w') as f:
    json.dump({"crib_hits": crib_hits,
               "top_results": sorted(all_results, key=lambda r: r['score'], reverse=True)[:30],
               "total_tested": len(tested)}, f, indent=2, default=str)
print(f"\nSaved to {RESULTS_DIR}/results.json")
print("Done.")
