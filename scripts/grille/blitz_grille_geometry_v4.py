#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Grille Geometry v4 — fast critical approaches:
1. Sub-region search: find rectangles with exactly 97 holes
2. 2-rotation Cardan on small grids (10×10 etc.)
3. Autokey cipher variants
4. Specific known-PT attacks using EASTNORTHEAST/BERLINCLOCK
5. Grille holes as PAIRED coordinates (Polybius-style bigrams)
6. KA tableau holes → permutation by tableau coordinate mod 97
"""

import json, sys, os, math
from collections import Counter

sys.path.insert(0, 'src')

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

GE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

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

RESULTS_DIR = "blitz_results/grille_geometry"
os.makedirs(RESULTS_DIR, exist_ok=True)
hits = []; all_results = []

def test_ct(ct, label_base):
    """Test a candidate CT with all keywords/ciphers."""
    best_sc = -1e9; best = {}
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(ct, kw, alpha)
                sc = score_per_char(pt)
                ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    r = {"label": f"{label_base}_{name}_{alpha_name}_{kw}",
                         "pt": pt, "score": sc, "ene_pos": ene, "bc_pos": bc}
                    print(f"\n{'!'*60}")
                    print(f"*** CRIB HIT: {r['label']}")
                    print(f"    ENE@{ene}  BC@{bc}")
                    print(f"    PT: {pt}")
                    print('!'*60)
                    hits.append(r)
                if sc > best_sc:
                    best_sc = sc
                    best = {"label": f"{label_base}_{name}_{alpha_name}_{kw}",
                            "pt": pt, "score": sc}
    if best: all_results.append(best)
    return best_sc

# Raw holes (no off-grid exclusion)
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
print(f"Total raw holes: {len(HOLES_RAW)}")

# ═══════════════════════════════════════════════════════════════
# APPROACH 1: Sub-region search for exactly 97 holes
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 1: Sub-region search (rectangles with 97 holes) ===")

# Build prefix sum for fast rectangle queries
MAX_R, MAX_C = 28, 35
psum = [[0]*(MAX_C+1) for _ in range(MAX_R+1)]
for r, c in HOLES_RAW:
    if r < MAX_R and c < MAX_C:
        psum[r+1][c+1] += 1
for r in range(1, MAX_R+1):
    for c in range(1, MAX_C+1):
        psum[r][c] += psum[r-1][c] + psum[r][c-1] - psum[r-1][c-1]

def count_holes(r1, c1, r2, c2):
    """Count holes in [r1,r2) × [c1,c2)."""
    r2 = min(r2, MAX_R); c2 = min(c2, MAX_C)
    return psum[r2][c2] - psum[r1][c2] - psum[r2][c1] + psum[r1][c1]

print(f"  Total holes in full grid: {count_holes(0, 0, MAX_R, MAX_C)}")

exact_97_rects = []
for top_r in range(MAX_R):
    for top_c in range(MAX_C):
        for bot_r in range(top_r+1, MAX_R+1):
            for bot_c in range(top_c+1, MAX_C+1):
                n = count_holes(top_r, top_c, bot_r, bot_c)
                if n == 97:
                    exact_97_rects.append((top_r, top_c, bot_r, bot_c))

print(f"  Rectangles with exactly 97 holes: {len(exact_97_rects)}")
for rect in exact_97_rects[:20]:
    print(f"    {rect}: {rect[2]-rect[0]}×{rect[3]-rect[1]}")

# For each 97-hole rectangle, build and test overlays
n_tested = 0
for top_r, top_c, bot_r, bot_c in exact_97_rects:
    h = bot_r - top_r
    w = bot_c - top_c
    # Holes in this rectangle
    rect_holes = sorted([(r-top_r, c-top_c) for r,c in HOLES_RAW
                         if top_r <= r < bot_r and top_c <= c < bot_c],
                        key=lambda x: (x[0], x[1]))
    if len(rect_holes) != 97:
        continue

    # Overlay: K4 written in w cols, holes select positions
    perm = [hr*w+hc for hr,hc in rect_holes if hr*w+hc < 97]
    if len(perm) == 97 and len(set(perm)) == 97:
        ct2 = ''.join(K4[p] for p in perm)
        sc = test_ct(ct2, f"1_rect{top_r}_{top_c}_{h}x{w}")
        n_tested += 1
        if sc > -7.5:
            print(f"  HIGH SCORE: rect({top_r},{top_c}) {h}×{w} → {sc:.4f}")

    # Also try: holes as direct K4 positions (mod 97)
    flat_mod97 = [((hr)*w + hc) % 97 for hr,hc in rect_holes]
    if len(set(flat_mod97)) == 97:
        ct2 = ''.join(K4[p] for p in flat_mod97)
        sc = test_ct(ct2, f"1b_rect{top_r}_{top_c}_{h}x{w}_mod97")
        n_tested += 1

print(f"  Tested {n_tested} rectangle overlay permutations")

# ═══════════════════════════════════════════════════════════════
# APPROACH 2: 2-rotation Cardan on various small grids
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 2: 2-rotation Cardan on small K4 grids ===")

def get_holes_in_rect_abs(all_holes, r1, c1, r2, c2):
    """Get holes in [r1,r2)×[c1,c2), return as (row-r1, col-c1)."""
    return sorted([(r-r1, c-c1) for r,c in all_holes
                  if r1 <= r < r2 and c1 <= c < c2],
                 key=lambda x: (x[0],x[1]))

def rotate180(holes, nr, nc):
    return [(nr-1-r, nc-1-c) for r,c in holes]

near_perfect = []
for nr in range(6, 20):
    for nc in range(6, 20):
        if nr*nc < 97:
            continue
        for top_r in range(MAX_R-nr+1):
            for top_c in range(MAX_C-nc+1):
                h1 = get_holes_in_rect_abs(HOLES_RAW, top_r, top_c, top_r+nr, top_c+nc)
                if not h1:
                    continue
                h2 = rotate180(h1, nr, nc)
                # Check coverage
                s1 = set(h1); s2 = set(h2)
                union_size = len(s1 | s2)
                overlap = len(s1 & s2)
                # We want: union covers all 97 K4 positions, no overlap
                if union_size == 97 and overlap == 0 and len(h1)+len(h2) == 97:
                    print(f"  *** PERFECT 2-ROT: ({top_r},{top_c}) {nr}×{nc}: "
                          f"|h1|={len(h1)}, |h2|={len(h2)}, union={union_size}")
                    near_perfect.append((top_r, top_c, nr, nc, h1, h2))
                elif 93 <= union_size <= 101 and overlap <= 5:
                    near_perfect.append((top_r, top_c, nr, nc, h1, h2))

print(f"  Near-perfect 2-rotation candidates: {len(near_perfect)}")

for top_r, top_c, nr, nc, h1, h2 in near_perfect[:5]:
    print(f"  rect({top_r},{top_c}) {nr}×{nc}: |h1|={len(h1)}, |h2|={len(h2)}")
    # Build permutation: h1 positions come first, then h2
    all_holes_flat = [r*nc+c for r,c in sorted(h1)] + [r*nc+c for r,c in sorted(h2)]
    # Filter to K4 range
    perm97 = [p for p in all_holes_flat if p < 97]
    perm97_dedup = list(dict.fromkeys(perm97))
    if len(perm97_dedup) == 97:
        ct2 = ''.join(K4[p] for p in perm97_dedup)
        sc = test_ct(ct2, f"2_2rot_{nr}x{nc}_r{top_r}c{top_c}")
        if sc > -7.5:
            print(f"  HIGH: sc={sc:.4f}")

# ═══════════════════════════════════════════════════════════════
# APPROACH 3: Autokey cipher variants
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 3: Autokey cipher variants ===")

def autokey_vig_dec(ct, seed, alpha=AZ):
    n = len(alpha); key = list(seed); pt = []
    for i, ch in enumerate(ct):
        k = alpha.index(key[i])
        c = alpha.index(ch)
        p_char = alpha[(c - k) % n]
        pt.append(p_char); key.append(p_char)
    return ''.join(pt)

def autokey_beau_dec(ct, seed, alpha=AZ):
    n = len(alpha); key = list(seed); pt = []
    for i, ch in enumerate(ct):
        k = alpha.index(key[i])
        c = alpha.index(ch)
        p_char = alpha[(k - c) % n]
        pt.append(p_char); key.append(p_char)
    return ''.join(pt)

def autokey_ct_vig(ct, seed, alpha=AZ):
    """Autokey with ciphertext extension."""
    n = len(alpha); key = list(seed) + list(ct); pt = []
    for i, ch in enumerate(ct):
        k = alpha.index(key[i])
        c = alpha.index(ch)
        pt.append(alpha[(c - k) % n])
    return ''.join(pt)

best_autokey = {"score": -1e9, "label": ""}
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    for kw in KEYWORDS:
        for name, fn in [("ak_vig", autokey_vig_dec), ("ak_beau", autokey_beau_dec),
                         ("ak_ct", autokey_ct_vig)]:
            try:
                pt = fn(K4, kw, alpha)
                sc = score_per_char(pt)
                ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                label = f"3_{name}_{kw}_{alpha_name}"
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
                    print(f"    PT: {pt}")
                    hits.append({"label": label, "pt": pt, "ene_pos": ene, "bc_pos": bc})
                if sc > best_autokey["score"]:
                    best_autokey = {"score": sc, "label": label, "pt": pt}
            except (ValueError, IndexError):
                pass

print(f"  Best autokey: {best_autokey['score']:.4f} ({best_autokey['label']})")
if best_autokey.get("pt"):
    print(f"    PT: {best_autokey['pt'][:60]}")

# ═══════════════════════════════════════════════════════════════
# APPROACH 4: Known-PT attack using partial cribs
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 4: Known-PT attack using partial cribs ===")

# The cribs MUST appear somewhere in PT. Specifically:
# PT contains "EASTNORTHEAST" (13 chars) and "BERLINCLOCK" (11 chars)
# Under the scrambled paradigm, these could be at ANY positions in PT.
#
# However, we can do a known-PT attack:
# For each possible start position p for ENE in PT (p=0..84):
#   For each possible permutation subset:
#     PT[p:p+13] = "EASTNORTHEAST"
#     So: REAL_CT[p:p+13] = vig_enc("EASTNORTHEAST", KEY[p:p+13])
#     These 13 real CT chars are AT SOME 13 K4 POSITIONS (the permutation)
#
# This is a partial constraint. We can use it to narrow down the key.

# If we ALSO know the key is KRYPTOS (7 chars), then:
# For each start position p:
#   real_CT[p:p+13] = vig_enc("EASTNORTHEAST", "KRYPTOS"[p:p+13])
#   = each of 13 known (plaintext letter, key letter) pairs → 13 real CT letters

def vig_enc(pt, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(pt[i])+alpha.index(key[i%len(key)]))%26] for i in range(len(pt)))

print("  Computing real_CT fragments for ENE crib at all positions with all keywords...")
ene_crib = "EASTNORTHEAST"
bc_crib = "BERLINCLOCK"

# For each keyword, compute what the real CT chars would be for the crib
crib_ct_fragments = {}
for kw in KEYWORDS:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        # For each crib position p in PT (0 to 84):
        for p in range(84):
            # Real CT at positions p to p+12 (for ENE crib)
            ene_real_ct = ''.join(alpha[(alpha.index(ene_crib[i])
                                        + alpha.index(kw[(p+i)%len(kw)])) % 26]
                                 for i in range(13))
            # Now: does this 13-char string appear as a SUBSEQUENCE of K4?
            # More specifically: do these 13 chars appear in K4 with the right letter counts?
            # Check if K4 has enough of each letter to form ene_real_ct
            ct_freq = Counter(K4)
            frag_freq = Counter(ene_real_ct)
            if all(ct_freq.get(ch,0) >= frag_freq[ch] for ch in frag_freq):
                label = f"4_ene_kw{kw}_{alpha_name}_p{p}"
                crib_ct_fragments[label] = (kw, alpha_name, ene_real_ct, p, "ENE")

print(f"  ENE fragments compatible with K4 letter frequencies: {len(crib_ct_fragments)}")
# Show first few
for k, (kw, an, frag, p, crib_type) in list(crib_ct_fragments.items())[:5]:
    print(f"    [{k}]: {frag} (kw={kw}, pos={p})")

# For BERLINCLOCK fragments
for kw in KEYWORDS:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for p in range(87):
            bc_real_ct = ''.join(alpha[(alpha.index(bc_crib[i])
                                       + alpha.index(kw[(p+i)%len(kw)])) % 26]
                                for i in range(11))
            ct_freq = Counter(K4)
            frag_freq = Counter(bc_real_ct)
            if all(ct_freq.get(ch,0) >= frag_freq[ch] for ch in frag_freq):
                label = f"4_bc_kw{kw}_{alpha_name}_p{p}"
                crib_ct_fragments[label] = (kw, alpha_name, bc_real_ct, p, "BC")

print(f"  Total compatible crib fragments (ENE+BC): {len(crib_ct_fragments)}")

# ═══════════════════════════════════════════════════════════════
# APPROACH 5: Grille holes as KA tableau coordinates → K4 permutation
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 5: KA tableau coordinate → K4 index ===")

# The KA tableau is 26 rows × 26 cols. Each cell (r,c) has value KA[(r+c)%26].
# If the Kryptos KA tableau starts at grille offset (dr, dc), then
# hole at (gr, gc) → tableau cell (gr-dr, gc-dc)
# → K4 index = tableau_row * 26 + tableau_col (mod 97)
# OR: K4 index = tableau_cell_value (0-25) then mapped to K4 somehow

def dedup97(seq):
    seen = set(); out = []
    for v in seq:
        v = v % 97
        if v not in seen: seen.add(v); out.append(v)
        if len(out) == 97: break
    return out if len(out) == 97 else None

for dr in range(4):
    for dc in range(8):
        # Get holes in tableau space (only valid tableau positions)
        t_holes = [(r-dr, c-dc) for r,c in HOLES_RAW if 0 <= r-dr < 26 and 0 <= c-dc < 26]
        if len(t_holes) < 97:
            continue
        t_holes_sorted = sorted(t_holes, key=lambda x: (x[0], x[1]))

        # Method A: (tr*26 + tc) mod 97
        p = dedup97(tr*26+tc for tr,tc in t_holes_sorted)
        if p:
            ct2 = ''.join(K4[i] for i in p)
            sc = test_ct(ct2, f"5a_dr{dr}_dc{dc}")
            if sc > -7.5:
                print(f"  HIGH 5a: dr={dr} dc={dc} sc={sc:.4f}")

        # Method B: (tc*26 + tr) mod 97
        p = dedup97(tc*26+tr for tr,tc in t_holes_sorted)
        if p:
            ct2 = ''.join(K4[i] for i in p)
            sc = test_ct(ct2, f"5b_dr{dr}_dc{dc}")
            if sc > -7.5:
                print(f"  HIGH 5b: dr={dr} dc={dc} sc={sc:.4f}")

        # Method C: KA letter value at (tr, tc) → ordering
        vals = [(KA[(tr+tc)%26], tr, tc) for tr,tc in t_holes_sorted]
        sorted_by_val = sorted(enumerate(vals), key=lambda x: (x[1][0], x[1][1], x[1][2]))
        argsort_p = [i for i,_ in sorted_by_val[:97]]
        if len(set(argsort_p)) == 97:
            ct2 = ''.join(K4[p] for p in argsort_p)
            sc = test_ct(ct2, f"5c_dr{dr}_dc{dc}")
            if sc > -7.5:
                print(f"  HIGH 5c: dr={dr} dc={dc} sc={sc:.4f}")

# ═══════════════════════════════════════════════════════════════
# APPROACH 6: T-avoidance constraint as permutation hint
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 6: T-avoidance as permutation constraint ===")

# The grille has no holes on T-positions in the KA tableau.
# In KA: T is at index 4. KA[(r+c)%26]=T iff (r+c)%26=4.
# So the "T anti-diagonals" have NO holes.
# Anti-diagonals: (r+c)=4, 30, 56, ... (mod 26) in the tableau.
# This means: in the 26×26 KA tableau (embedded in 28×33 grille),
# cells with r+c ≡ 4 (mod 26) have no holes.

# What if we use the T-anti-diagonal positions as the permutation?
# Specifically: in the 28×33 grid (or KA tableau), positions where
# the NEXT step would cross a T anti-diagonal define the permutation.

# For KA tableau (dr=1, dc=4 offset from grille top-left):
for dr in range(3):
    for dc in range(6):
        # T positions in grille: where (r-dr + c-dc) % 26 == 4
        t_positions_in_grille = []
        for r in range(28):
            for c in range(34):
                if 0 <= r-dr < 26 and 0 <= c-dc < 26:
                    if (r-dr + c-dc) % 26 == 4:
                        t_positions_in_grille.append((r, c))

        if len(t_positions_in_grille) >= 97:
            # Use T-position flat indices as permutation source
            t_flat = sorted(r*33+c for r,c in t_positions_in_grille)
            p = dedup97(t_flat)
            if p:
                ct2 = ''.join(K4[i] for i in p)
                sc = test_ct(ct2, f"6_T_antidiag_dr{dr}_dc{dc}")
                if sc > -7.5:
                    print(f"  HIGH 6: dr={dr} dc={dc} sc={sc:.4f}")

# ═══════════════════════════════════════════════════════════════
# APPROACH 7: GE letter frequencies as a Beaufort auto-key
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 7: GE repeated/padded as key variants ===")

# Try GE with all possible starting positions and lengths
GE_LONG = GE * 5  # repeat for safety

best_ge_score = -1e9
for start in range(len(GE)):
    key = GE_LONG[start:start+97]
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, key, alpha)
            sc = score_per_char(pt)
            ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
            if ene >= 0 or bc >= 0:
                print(f"\n*** CRIB HIT 7_ge{start}_{name}_{alpha_name}: ENE@{ene} BC@{bc}")
                print(f"    PT: {pt}")
                hits.append({"label": f"7_ge{start}_{name}_{alpha_name}", "pt": pt,
                              "ene_pos": ene, "bc_pos": bc})
            if sc > best_ge_score:
                best_ge_score = sc
                print(f"  New best GE key (start={start}, {name}, {alpha_name}): {sc:.4f}")

print(f"\n  Best GE-repeated key score: {best_ge_score:.4f}")

# ═══════════════════════════════════════════════════════════════
# APPROACH 8: Bigram-based Polybius from consecutive hole pairs
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH 8: Bigram hole coordinates as Polybius ===")

# Each PAIR of consecutive holes in reading order → (row1, col1, row2, col2) → letter
# This is like a super-Polybius square using hole pairs

holes_rc = sorted(HOLES_RAW, key=lambda h: (h[0], h[1]))

# Method A: consecutive pairs → row1*26+col1 as shift for K4
# (i.e., treat each hole's row as a Vigenère key letter for one K4 char)
if len(holes_rc) >= 97:
    # Use hole row values (0-27 → mod 26) as Vigenère key
    key_from_rows = ''.join(AZ[holes_rc[i][0] % 26] for i in range(97))
    key_from_cols = ''.join(AZ[holes_rc[i][1] % 26] for i in range(97))
    key_from_sum  = ''.join(AZ[(holes_rc[i][0] + holes_rc[i][1]) % 26] for i in range(97))
    key_from_diff = ''.join(AZ[abs(holes_rc[i][0] - holes_rc[i][1]) % 26] for i in range(97))

    for kname, key in [("rows", key_from_rows), ("cols", key_from_cols),
                       ("sum", key_from_sum), ("diff", key_from_diff)]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(K4, key, alpha)
                sc = score_per_char(pt)
                ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                label = f"8_{kname}_{name}_{alpha_name}"
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
                    print(f"    PT: {pt}")
                    hits.append({"label": label, "pt": pt, "ene_pos": ene, "bc_pos": bc})
                if sc > -7.0:
                    print(f"  HIGH [{label}] sc={sc:.4f}  PT: {pt[:60]}")
                all_results.append({"label": label, "pt": pt, "score": sc})

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("SUMMARY")
print("="*60)

if hits:
    print(f"\n{'!'*60}\nCRIB HITS: {len(hits)}")
    for h in hits:
        print(f"  [{h['label']}]  ENE@{h.get('ene_pos','?')}  BC@{h.get('bc_pos','?')}")
        print(f"  PT: {h['pt']}")
else:
    print("\nNo crib hits found.")

if all_results:
    top = sorted(all_results, key=lambda r: r['score'], reverse=True)[:10]
    print("\nTop 10 by quadgram score:")
    for r in top:
        print(f"  [{r['label'][:50]:50s}] sc={r['score']:.4f}")
        print(f"    PT: {r['pt'][:70]}")

with open(f"{RESULTS_DIR}/results_v4.json", 'w') as f:
    json.dump({"hits": hits,
               "top_results": sorted(all_results, key=lambda r: r['score'], reverse=True)[:20]},
              f, indent=2, default=str)
print(f"\nSaved. Done.")
