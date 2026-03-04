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
Grille Geometry v3 — targeted approaches based on v1/v2 null results.

New strategies:
1. Known-plaintext attack: if GE is PT, what's the implied key?
2. Exhaustive 3-4 letter key scan (no permutation)
3. GE first-occurrence ordering as cipher key
4. Autokey cipher variants
5. Sub-region search: find 97-hole rectangle in the grille
6. 2-rotation Cardan on small K4 grids
7. GE as repeated running key with various start offsets (brute-force good scores)
"""

import json, sys, os, math, itertools
from collections import Counter
import multiprocessing as mp

sys.path.insert(0, 'src')

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

GE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GE) == 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
            'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA']

QG = json.load(open('data/english_quadgrams.json'))

def score_per_char(text):
    t = text.upper(); n = len(t)-3
    return sum(QG.get(t[i:i+4],-10.) for i in range(n))/n if n>0 else -10.

def vig_dec(ct, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(ct[i])-alpha.index(key[i%len(key)]))%26] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(key[i%len(key)])-alpha.index(ct[i]))%26] for i in range(len(ct)))

def crib_check(pt):
    return pt.find("EASTNORTHEAST"), pt.find("BERLINCLOCK")

RESULTS_DIR = "blitz_results/grille_geometry"
os.makedirs(RESULTS_DIR, exist_ok=True)
hits = []

def hit(label, pt, key, cipher, alpha):
    ene, bc = crib_check(pt)
    print(f"\n{'!'*60}")
    print(f"*** CRIB HIT: {label}")
    print(f"    ENE@{ene}  BC@{bc}  key={key}  {cipher}/{alpha}")
    print(f"    PT: {pt}")
    print(f"    Score: {score_per_char(pt):.4f}")
    print('!'*60)
    hits.append({"label": label, "pt": pt, "ene_pos": ene, "bc_pos": bc,
                 "key": key, "cipher": cipher, "alpha": alpha})

# ═══════════════════════════════════════════════════════════════
# APPROACH 1: Known-plaintext attack — GE as PT
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 1: Known-plaintext attack (GE as PT) ===")

def implied_key(ct, pt, alpha):
    """For Vigenère: key[i] = (ct[i] - pt[i]) mod 26 in alpha space."""
    return [alpha.index(ct[i]) - (alpha.index(pt[i]) if pt[i] in alpha else 0) for i in range(min(len(ct),len(pt)))]

def find_period(key_indices, max_period=30):
    """Find if key has a period p by checking consistency."""
    n = len(key_indices)
    results = {}
    for p in range(1, min(max_period+1, n)):
        # For each period, compute how many positions are consistent (mod p)
        groups = {}
        for i, v in enumerate(key_indices):
            groups.setdefault(i%p, []).append(v)
        # For each group, count most common value
        consistent = sum(Counter(vs).most_common(1)[0][1] for vs in groups.values())
        results[p] = consistent
    return results

# Test GE[:97] as plaintext for K4 with Vigenère
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    for ge_start in range(10):
        ge_pt = GE[ge_start:ge_start+97]
        if len(ge_pt) < 97: continue

        # For Vigenère: key[i] = (K4[i] - ge_pt[i]) mod 26
        try:
            key_indices = [(alpha.index(K4[i]) - (alpha.index(ge_pt[i]) if ge_pt[i] in alpha else 0)) % 26
                          for i in range(97)]
            periods = find_period(key_indices, 30)
            # Show periods with high consistency
            best_p = max(range(1,31), key=lambda p: periods[p])
            best_consistent = periods[best_p]
            if best_consistent >= 87:  # 90%+ consistent
                print(f"  GE[{ge_start}:] PT, Vig, {alpha_name}: period={best_p}, consistent={best_consistent}/97")
                # Extract the implied key
                key_at_period = [Counter([key_indices[i] for i in range(j, 97, best_p)]).most_common(1)[0][0]
                                for j in range(best_p)]
                implied = ''.join(alpha[v] for v in key_at_period)
                print(f"    Implied key: {implied}")
                # Test this key
                pt = vig_dec(K4, implied, alpha)
                ene, bc = crib_check(pt)
                if ene >= 0 or bc >= 0:
                    hit(f"1a_kpa_vig_ge{ge_start}_{alpha_name}", pt, implied, "vig", alpha_name)
        except (ValueError, IndexError):
            pass

        # For Beaufort: key[i] = (ge_pt[i] + K4[i]) mod 26
        try:
            key_indices_b = [(alpha.index(ge_pt[i]) + alpha.index(K4[i])) % 26
                            if ge_pt[i] in alpha and K4[i] in alpha else 0
                            for i in range(97)]
            periods_b = find_period(key_indices_b, 30)
            best_p_b = max(range(1,31), key=lambda p: periods_b[p])
            best_con_b = periods_b[best_p_b]
            if best_con_b >= 87:
                print(f"  GE[{ge_start}:] PT, Beau, {alpha_name}: period={best_p_b}, consistent={best_con_b}/97")
                key_at_p_b = [Counter([key_indices_b[i] for i in range(j, 97, best_p_b)]).most_common(1)[0][0]
                             for j in range(best_p_b)]
                implied_b = ''.join(alpha[v] for v in key_at_p_b)
                print(f"    Implied key (Beau): {implied_b}")
                pt = beau_dec(K4, implied_b, alpha)
                ene, bc = crib_check(pt)
                if ene >= 0 or bc >= 0:
                    hit(f"1b_kpa_beau_ge{ge_start}_{alpha_name}", pt, implied_b, "beau", alpha_name)
        except (ValueError, IndexError):
            pass

# Print period consistency for best case (ge_start=0, AZ)
print("\n  Period analysis for GE[:97] as PT, Vig, AZ:")
try:
    key_idx0 = [(AZ.index(K4[i]) - AZ.index(GE[i])) % 26 for i in range(97)]
    p_results = find_period(key_idx0, 30)
    for p in range(1, 31):
        print(f"    Period {p:2d}: consistency {p_results[p]:3d}/97 = {100*p_results[p]/97:.1f}%")
except (ValueError, IndexError) as e:
    print(f"  Error: {e}")

# ═══════════════════════════════════════════════════════════════
# APPROACH 2: Exhaustive 3-letter key scan (no permutation)
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 2: All 2-4 letter keys direct on K4 ===")

best_direct = {"score": -1e9, "label": "", "pt": ""}
n_tested = 0

for klen in [2, 3, 4]:
    for key_tuple in itertools.product(AZ, repeat=klen):
        key = ''.join(key_tuple)
        for alpha in [AZ, KA]:
            for fn in [vig_dec, beau_dec]:
                pt = fn(K4, key, alpha)
                sc = score_per_char(pt)
                ene, bc = crib_check(pt)
                if ene >= 0 or bc >= 0:
                    nm = "vig" if fn == vig_dec else "beau"
                    an = "AZ" if alpha == AZ else "KA"
                    hit(f"2_direct_{klen}_{key}_{nm}_{an}", pt, key, nm, an)
                if sc > best_direct["score"]:
                    best_direct = {"score": sc, "label": f"klen{klen}_{key}_{fn.__name__}",
                                   "pt": pt, "key": key}
                n_tested += 1
    print(f"  klen={klen}: done ({n_tested} total tests so far). Best: {best_direct['score']:.4f} ({best_direct['label']})")

print(f"\n  Best from direct scan: score={best_direct['score']:.4f}")
print(f"  Label: {best_direct['label']}")
print(f"  PT: {best_direct['pt']}")

# ═══════════════════════════════════════════════════════════════
# APPROACH 3: GE first-occurrence order as 25-char key
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 3: GE unique letter order as key ===")

ge_unique_order = []
seen = set()
for ch in GE:
    if ch not in seen:
        seen.add(ch); ge_unique_order.append(ch)
ge_key25 = ''.join(ge_unique_order)  # 25 letters (no T)
print(f"GE unique order (key25): {ge_key25}")

# Test ge_key25 and variants
keys_to_test = [
    ("ge25", ge_key25),
    ("ge25_rev", ge_key25[::-1]),
]
# Also insert T at various positions
for tpos in [0, 4, 7, 12, 24, 25]:
    kk = ge_key25[:tpos] + 'T' + ge_key25[tpos:]
    keys_to_test.append((f"ge26_T{tpos}", kk))

# Also: ge25 repeated to fill 97 chars
ge_key97 = (ge_key25 * 4)[:97]
keys_to_test.append(("ge25_rep97", ge_key97))

# And: use GE itself as key (106 chars)
for ge_start in range(10):
    k = GE[ge_start:]
    keys_to_test.append((f"GE_start{ge_start}", k))

for kname, kk in keys_to_test:
    if len(kk) == 0: continue
    # Filter to only valid alpha chars
    kk_az = ''.join(c for c in kk if c in AZ)
    if not kk_az: continue
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, kk_az, alpha)
            sc = score_per_char(pt)
            ene, bc = crib_check(pt)
            label = f"3_{kname}_{name}_{alpha_name}"
            if ene >= 0 or bc >= 0:
                hit(label, pt, kk_az[:20], name, alpha_name)
            if sc > -7.0:
                print(f"  HIGH [{label}] sc={sc:.4f}  PT: {pt[:60]}")

# ═══════════════════════════════════════════════════════════════
# APPROACH 4: Autokey cipher variants
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 4: Autokey cipher variants ===")

def autokey_vig_dec(ct, seed, alpha=AZ):
    """Autokey Vigenère decrypt: key extends with plaintext."""
    n = len(alpha)
    key = list(seed)
    pt = []
    for i, ch in enumerate(ct):
        k = alpha.index(key[i])
        c = alpha.index(ch)
        p_char = alpha[(c - k) % n]
        pt.append(p_char)
        key.append(p_char)
    return ''.join(pt[:len(ct)])

def autokey_beau_dec(ct, seed, alpha=AZ):
    """Autokey Beaufort decrypt: key extends with plaintext."""
    n = len(alpha)
    key = list(seed)
    pt = []
    for i, ch in enumerate(ct):
        k = alpha.index(key[i])
        c = alpha.index(ch)
        p_char = alpha[(k - c) % n]
        pt.append(p_char)
        key.append(p_char)
    return ''.join(pt[:len(ct)])

def autokey_ct_vig_dec(ct, seed, alpha=AZ):
    """Autokey Vigenère decrypt with ciphertext extension."""
    n = len(alpha)
    key = list(seed) + list(ct)  # key = seed + ciphertext
    pt = []
    for i, ch in enumerate(ct):
        k = alpha.index(key[i])
        c = alpha.index(ch)
        pt.append(alpha[(c - k) % n])
    return ''.join(pt)

for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    # Autokey with each standard keyword as seed
    for kw in KEYWORDS:
        for name, fn in [("ak_vig", autokey_vig_dec), ("ak_beau", autokey_beau_dec),
                         ("ak_ct_vig", autokey_ct_vig_dec)]:
            try:
                pt = fn(K4, kw, alpha)
                ene, bc = crib_check(pt)
                label = f"4_{name}_{kw}_{alpha_name}"
                if ene >= 0 or bc >= 0:
                    hit(label, pt, kw, name, alpha_name)
                sc = score_per_char(pt)
                if sc > -7.0:
                    print(f"  HIGH [{label}] sc={sc:.4f}  PT: {pt[:60]}")
            except (ValueError, IndexError):
                pass

    # Autokey with GE as seed
    for ge_seed_len in [7, 9, 11, 13, 25, 26]:
        ge_seed = GE[:ge_seed_len]
        for name, fn in [("ak_vig", autokey_vig_dec), ("ak_beau", autokey_beau_dec)]:
            try:
                pt = fn(K4, ge_seed, alpha)
                ene, bc = crib_check(pt)
                label = f"4_{name}_ge{ge_seed_len}_{alpha_name}"
                if ene >= 0 or bc >= 0:
                    hit(label, pt, ge_seed, name, alpha_name)
                sc = score_per_char(pt)
                if sc > -7.0:
                    print(f"  HIGH [{label}] sc={sc:.4f}  PT: {pt[:60]}")
            except (ValueError, IndexError):
                pass

# ═══════════════════════════════════════════════════════════════
# APPROACH 5: Sub-region search for exactly 97 holes
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 5: Find rectangular sub-region with ~97 holes ===")

# Load all raw holes (no off-grid exclusion)
MASK_DATA_RAW = [
    "000000001010100000000010000000001",
    "100000000010000001000100110000011",
    "000000000000001000000000000000011",
    "00000000000000000000100000010011",
    "00000001000000001000010000000011",
    "000000001000000000000000000000011",
    "100000000000000000000000000000011",
    "00000000000000000000000100000100",
    "0000000000000000000100000001000",
    "0000000000000000000000000000100",
    "000000001000000000000000000000",
    "00000110000000000000000000000100",
    "00000000000000100010000000000001",
    "00000000000100000000000000001000",
    "000110100001000000000000001000010",
    "00001010000000000000000001000001",
    "001001000010010000000000000100010",
    "00000000000100000000010000010001",
    "000000000000010001001000000010001",
    "00000000000000001001000000000100",
    "000000001100000010100100010001001",
    "000000000000000100001010100100011",
    "00000000100000000000100001100001",
    "100000000000000000001000001000010",
    "10000001000001000000100000000001",
    "000010000000000000010000100000011",
    "000000000000000000010000100000011",
    "00000000000000100000001010000001",
]

HOLES_RAW = []
for r, row_str in enumerate(MASK_DATA_RAW):
    for c, ch in enumerate(row_str):
        if ch == '1':
            HOLES_RAW.append((r, c))
print(f"Raw holes: {len(HOLES_RAW)}")

# Build a 2D grid
hole_set = set(HOLES_RAW)

# Search for rectangles containing ~97 holes
# Try all (dr, dc, height, width) combinations
print("  Searching for rectangles with 95-99 holes...")
found_regions = []
for top_r in range(28):
    for top_c in range(33):
        for height in range(1, 28-top_r+1):
            for width in range(1, 33-top_c+1):
                # Count holes in this rectangle
                n_holes = sum(1 for r,c in HOLES_RAW
                             if top_r <= r < top_r+height and top_c <= c < top_c+width)
                if 95 <= n_holes <= 99:
                    found_regions.append((top_r, top_c, height, width, n_holes))

print(f"  Found {len(found_regions)} rectangles with 95-99 holes")
for top_r, top_c, height, width, n_holes in found_regions[:20]:
    print(f"    rect({top_r},{top_c}) {height}×{width} → {n_holes} holes")

# For rectangles with EXACTLY 97 holes, use them as overlays
exact_97 = [(top_r, top_c, h, w) for top_r, top_c, h, w, n in found_regions if n == 97]
print(f"  Rectangles with exactly 97 holes: {len(exact_97)}")

for top_r, top_c, height, width in exact_97[:10]:
    # Extract holes in this rectangle, sorted by reading order
    rect_holes = sorted([(r-top_r, c-top_c) for r,c in HOLES_RAW
                         if top_r <= r < top_r+height and top_c <= c < top_c+width],
                        key=lambda h: (h[0], h[1]))
    # Map to K4 positions
    # K4 laid out in `width` cols, holes (r,c) → K4[r*width+c]
    perm_rect = [h[0]*width+h[1] for h in rect_holes if h[0]*width+h[1] < 97]
    if len(perm_rect) == 97 and len(set(perm_rect)) == 97:
        ct2 = ''.join(K4[p] for p in perm_rect)
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for kw in KEYWORDS:
                for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                    pt = fn(ct2, kw, alpha)
                    ene, bc = crib_check(pt)
                    if ene >= 0 or bc >= 0:
                        hit(f"5_rect{top_r}_{top_c}_{height}x{width}_{name}_{alpha_name}_{kw}",
                            pt, kw, name, alpha_name)

# ═══════════════════════════════════════════════════════════════
# APPROACH 6: 2-rotation Cardan on small grids
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 6: 2-rotation Cardan grille on small K4 grids ===")

def rotate180_holes(holes, max_r, max_c):
    return [(max_r-1-r, max_c-1-c) for r,c in holes]

def get_holes_in_rect(all_holes, top_r, top_c, h, w):
    return sorted([(r-top_r, c-top_c) for r,c in all_holes
                  if top_r <= r < top_r+h and top_c <= c < top_c+w],
                 key=lambda x: (x[0],x[1]))

# For various K4 grid sizes (nr × nc, nr*nc ≥ 97)
for nr in range(7, 15):
    nc = math.ceil(97/nr)
    n_cells = nr * nc
    # Look for a grille sub-region that covers 97/2 ≈ 48-49 holes per rotation
    target = math.ceil(97/2)
    print(f"  Trying {nr}×{nc} K4 grid, target ~{target} holes per half")

    for top_r in range(28-nr+1):
        for top_c in range(33-nc+1):
            h1 = get_holes_in_rect(HOLES_RAW, top_r, top_c, nr, nc)
            # Rotation 180°
            h2 = rotate180_holes(h1, nr, nc)
            # Check if h1 and h2 together cover all nr*nc cells without overlap
            s1 = set(h1)
            s2 = set(h2)
            overlap = len(s1 & s2)
            coverage = len(s1 | s2)
            if abs(len(h1) + len(h2) - n_cells) <= 3 and overlap == 0:
                print(f"    NEAR-PERFECT: rect({top_r},{top_c}) {nr}×{nc}: "
                      f"h1={len(h1)}, h2={len(h2)}, overlap={overlap}, coverage={coverage}/{n_cells}")
                # Build permutation from h1 (positions in h1 = first half of reading)
                # then h2 (remaining positions)
                perm = []
                # Positions in h1 come from one set, h2 from another
                all_pos = sorted(range(n_cells))
                h1_flat = [hh[0]*nc+hh[1] for hh in h1]
                h2_flat = [hh[0]*nc+hh[1] for hh in h2]
                perm = h1_flat + h2_flat
                perm97 = [p for p in perm if p < 97]
                if len(perm97) == 97 and len(set(perm97)) == 97:
                    ct2 = ''.join(K4[p] for p in perm97)
                    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                        for kw in KEYWORDS:
                            for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                                pt = fn(ct2, kw, alpha)
                                ene, bc = crib_check(pt)
                                if ene >= 0 or bc >= 0:
                                    hit(f"6_2rot_{nr}x{nc}_r{top_r}c{top_c}_{name}_{kw}",
                                        pt, kw, name, alpha_name)

# ═══════════════════════════════════════════════════════════════
# APPROACH 7: Score all columnar permutations with full key scan
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 7: Best-scoring columnar perm with ALL 5-7 char keywords ===")

# Find the single best columnar width from v1 (w=61, score=-7.64)
# and do a more exhaustive keyword search on it
def col_read_perm(width, n=97):
    nr = math.ceil(n/width)
    return [r*width+c for c in range(width) for r in range(nr) if r*width+c < n]

p61 = col_read_perm(61)
ct61 = ''.join(K4[p] for p in p61)

p82 = col_read_perm(82)
ct82 = ''.join(K4[p] for p in p82)

print("  Testing col_w61 with all 5-7 char keywords...")
best_5to7 = {"score": -1e9, "label": "", "pt": ""}
n_keys = 0
for klen in [5, 6, 7]:
    for key_tuple in itertools.product(AZ, repeat=klen):
        key = ''.join(key_tuple)
        n_keys += 1
        if n_keys % 1000000 == 0:
            print(f"    {n_keys} keys tested, best so far: {best_5to7['score']:.4f} ({best_5to7['label']})")
        for alpha in [AZ]:  # just AZ for speed
            pt = vig_dec(ct61, key, alpha)
            sc = score_per_char(pt)
            ene, bc = crib_check(pt)
            if ene >= 0 or bc >= 0:
                print(f"\n*** CRIB HIT: col61+vig+{key}  ENE@{ene} BC@{bc}")
                print(f"    PT: {pt}")
                hits.append({"label": f"7_col61_vig_{key}", "pt": pt, "ene_pos": ene, "bc_pos": bc})
            if sc > best_5to7["score"]:
                best_5to7 = {"score": sc, "label": f"col61_vig_{key}", "pt": pt, "key": key}
        if klen >= 6:
            break  # Only do 6-char for a limited subset to avoid too long runtime
    print(f"  klen={klen} done. Best: {best_5to7['score']:.4f} ({best_5to7['label']})")
    if klen >= 6:
        print("  (Skipping longer keys for time - breakthrough threshold not reached)")
        break

# ═══════════════════════════════════════════════════════════════
# APPROACH 8: GE as a KA-modified Vigenère key
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 8: GE letters indexed in KA alphabet as key ===")

# The GE letters are extracted from the KA Vigenère tableau
# Each GE letter has a specific MEANING in the KA context:
# - Its position in the KA alphabet gives a shift value
# - These shift values form a running key

ge_ka_indices = [KA.index(c) if c in KA else 25 for c in GE]
ge_az_indices = [AZ.index(c) for c in GE]
print(f"GE KA indices (first 20): {ge_ka_indices[:20]}")
print(f"GE AZ indices (first 20): {ge_az_indices[:20]}")

# Use KA indices as direct shifts for K4
for ge_start in range(10):
    ki = ge_ka_indices[ge_start:ge_start+97]
    ai = ge_az_indices[ge_start:ge_start+97]
    if len(ki) < 97: continue

    # Shift K4 by KA indices
    ct_shifted_ka = ''.join(AZ[(AZ.index(K4[i]) - ki[i]) % 26] for i in range(97))
    ct_shifted_ka_beau = ''.join(AZ[(ki[i] - AZ.index(K4[i])) % 26] for i in range(97))
    ct_shifted_az = ''.join(AZ[(AZ.index(K4[i]) - ai[i]) % 26] for i in range(97))
    ct_shifted_az_beau = ''.join(AZ[(ai[i] - AZ.index(K4[i])) % 26] for i in range(97))

    for name, shifted in [("vig_ka", ct_shifted_ka), ("beau_ka", ct_shifted_ka_beau),
                          ("vig_az", ct_shifted_az), ("beau_az", ct_shifted_az_beau)]:
        for kw in KEYWORDS:
            for fn_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    pt = fn(shifted, kw, alpha)
                    ene, bc = crib_check(pt)
                    label = f"8_ge{ge_start}_{name}_{fn_name}_{alpha_name}_{kw}"
                    if ene >= 0 or bc >= 0:
                        hit(label, pt, kw, fn_name, alpha_name)

# ═══════════════════════════════════════════════════════════════
# APPROACH 9: The tableau coordinates of holes → permutation
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 9: KA tableau coordinates → direct K4 index mapping ===")

# The KA tableau is 26×26. If embedded in the 28×33 grille at offset (dr, dc),
# then hole at (r,c) → tableau (r-dr, c-dc) → K4 index = (tr*26 + tc) % 97

def dedup(seq, n=97):
    seen = set(); out = []
    for v in seq:
        v = v % n
        if v not in seen: seen.add(v); out.append(v)
        if len(out) == n: break
    return out if len(out) == n else None

for dr in range(3):
    for dc in range(8):
        # holes in tableau space
        tableau_holes = [(r-dr, c-dc) for r,c in HOLES_RAW
                         if 0 <= r-dr < 26 and 0 <= c-dc < 26]
        tableau_flat = [(th[0]*26 + th[1]) for th in sorted(tableau_holes)]
        p = dedup(tableau_flat)
        if p:
            ct2 = ''.join(K4[i] for i in p)
            for kw in KEYWORDS:
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                        pt = fn(ct2, kw, alpha)
                        ene, bc = crib_check(pt)
                        if ene >= 0 or bc >= 0:
                            hit(f"9_tableau_dr{dr}_dc{dc}_{name}_{alpha_name}_{kw}",
                                pt, kw, name, alpha_name)

# ═══════════════════════════════════════════════════════════════
# APPROACH 10: Grille holes as Polybius square coordinates
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 10: Polybius square via hole coordinates ===")

# In the KA tableau, hole at (r,c) can be read as a "coordinate pair"
# encoding one plaintext letter via a Polybius square.
# If we take PAIRS of holes as (row_coord, col_coord) → one letter...
# 107 holes → 53 pairs → only 53 letters (too few for 97-char K4)

# Alternative: treat each hole's (r%5, c%5) as Polybius square coordinates
# and use the resulting sequence to decrypt K4

for dr in range(5):
    for dc in range(5):
        poly_seq = [(r+dr)%26 for r,c in HOLES_RAW[:97]]  # use row as shift
        ct2 = ''.join(AZ[(AZ.index(K4[i]) - poly_seq[i]) % 26] for i in range(97))
        for kw in KEYWORDS:
            for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(ct2, kw, AZ)
                ene, bc = crib_check(pt)
                if ene >= 0 or bc >= 0:
                    hit(f"10_poly_dr{dr}_dc{dc}_{name}_{kw}", pt, kw, name, "AZ")

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("FINAL SUMMARY")
print("="*60)

if hits:
    print(f"\n{'!'*60}\nCRIB HITS: {len(hits)}")
    for h in hits:
        print(f"  [{h['label']}]  ENE@{h['ene_pos']}  BC@{h['bc_pos']}")
        print(f"  PT: {h['pt']}")
else:
    print("\nNo crib hits found.")

print(f"\nBest from direct 2-4 char key scan: sc={best_direct['score']:.4f}")
print(f"  {best_direct['label']}: {best_direct['pt'][:60]}")

with open(f"{RESULTS_DIR}/results_v3.json", 'w') as f:
    json.dump({"hits": hits, "best_direct": best_direct}, f, indent=2, default=str)
print(f"\nSaved to {RESULTS_DIR}/results_v3.json\nDone.")
