#!/usr/bin/env python3
"""
blitz_ka_cycle_grille.py

Test AZ->KA permutation cycle structure as Cardan grille definition.

Approaches A-H + permutation reordering:
  A: Cipher letter cycle membership -> hole/solid
  B: Cipher letter cycle-INDEX parity -> hole/solid
  C: Apply perm N times to cipher letter, check cycle membership
  D: Tableau letter cycle membership -> hole/solid
  E: Row key-column letter cycle -> entire row rule; header letter -> entire col rule
  F: KA-index difference (cipher - tableau) cycle membership
  G: K3 verification (do holes in K3 reconstruct K3 PT?)
  H: Row cycle AND/OR/XOR column cycle -> combined mask
  P: Permutation reordering of K4 by cycle index (descramble)
  R: 180-degree rotation partners
"""

import sys, json, math, itertools
from collections import Counter, defaultdict

# ============================================================
# CONSTANTS
# ============================================================
AZ = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
assert len(KA) == 26 and len(set(KA)) == 26

K4_CARVED = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
assert len(K4_CARVED) == 97

KEYWORDS = [
    'KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
    'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA',
    'KRYPTOSABCDE','NORTHBYEAST','NORTHEAST','LAYER',
]

CIPHER_ROWS = [
    'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV',   # row 0  K1
    'JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF',   # row 1
    'DVFPJUDEEHZWETZYVGWHKKQETGFQJNC',   # row 2
    'EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG',  # row 3  (? at col 7)
    'TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA',   # row 4
    'QZGZLECGYUXUEENJTBJLBQCETBJDFHR',   # row 5
    'RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT',   # row 6
    'IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER',   # row 7  (? at col 9)
    'EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI',   # row 8
    'DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK',   # row 9
    'FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ',   # row 10
    'ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE',   # row 11
    'DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP',   # row 12
    'DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG',   # row 13  K2 ends
    'ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI',   # row 14  K3 starts (CENTER)
    'ACHTNREYULDSLLSLLNOHSNOSMRWXMNE',   # row 15
    'TPRNGATIHNRARPESLNNELEBLPIIACAE',    # row 16
    'WMTWNDITEENRAHCTENEUDRETNHAEOET',   # row 17
    'FOLSEDTIWENHAEIOYTEYQHEENCTAYCR',   # row 18
    'EIFTBRSPAMHHEWENATAMATEGYEERLBT',   # row 19
    'EEFOASFIOTUETUAEOTOARMAEERTNRTI',   # row 20
    'BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB',   # row 21
    'AECTDDHILCEIHSITEGOEAOSDDRYDLOR',   # row 22
    'ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE',   # row 23
    'ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR',   # row 24  K4@col27  (? at col 26)
    'UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO',   # row 25
    'TWTQSJQSSEKZZWATJKLUDIAWINFBNYP',   # row 26
    'VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR',   # row 27
]
assert len(CIPHER_ROWS) == 28
for i, row in enumerate(CIPHER_ROWS):
    assert len(row) == 31, f"Row {i} has {len(row)} chars"

# ============================================================
# AZ->KA PERMUTATION AND CYCLES
# ============================================================
perm = {AZ[i]: KA[i] for i in range(26)}

def build_cycles():
    visited = set()
    cycles = []
    for start in AZ:
        if start in visited:
            continue
        cycle, cur = [], start
        while cur not in visited:
            visited.add(cur)
            cycle.append(cur)
            cur = perm[cur]
        cycles.append(tuple(cycle))
    return sorted(cycles, key=lambda x: -len(x))

cycles = build_cycles()
cycle_17 = set(cycles[0])   # 17-cycle: A,K,D,P,I,B,R,L,E,T,N,G,S,M,F,O,H
cycle_8  = set(cycles[1])   # 8-cycle:  C,Y,X,W,V,U,Q,J
cycle_1  = set(cycles[2])   # fixed: Z

letter_cycle_size = {}
letter_cycle_idx  = {}
for c in cycles:
    for i, letter in enumerate(c):
        letter_cycle_size[letter] = len(c)
        letter_cycle_idx[letter]  = i

print("=== AZ->KA CYCLE DECOMPOSITION ===")
print(f"17-cycle ({len(cycle_17)}): {''.join(sorted(cycle_17))}")
print(f" 8-cycle ({len(cycle_8)}):  {''.join(sorted(cycle_8))}")
print(f" 1-cycle: Z")
print(f"Cycle order: {', '.join(str(len(c)) for c in cycles)} => LCM={17*8}")

# ============================================================
# BUILD TABLEAU (28x31)
# Col 0 = key letter (blank/A-Z/blank)
# Cols 1-30 = KA body: KA[(r-1 + c-1) % 26] for r=1..26, c=1..30
# ============================================================
def build_tableau():
    tab = []
    hdr = ' ' + ''.join(AZ[(c) % 26] for c in range(30))  # header = ' ' + AZ wrapping
    tab.append(hdr)
    for r in range(1, 27):
        key  = AZ[r - 1]
        body = ''.join(KA[(r - 1 + c) % 26] for c in range(30))
        tab.append(key + body)
    tab.append(hdr)   # footer = header
    return tab

tableau = build_tableau()
assert len(tableau) == 28
for i, row in enumerate(tableau):
    assert len(row) == 31, f"Tableau row {i}: {len(row)} chars"

# Quick sanity: row 14 (key=N) body should start with G
assert tableau[14][1] == 'G', f"Tableau[14][1]={tableau[14][1]}, expected G"
# row 1 (key=A) col 1 = K (KA[0])
assert tableau[1][1] == 'K', f"Tableau[1][1]={tableau[1][1]}, expected K"

# ============================================================
# K4 POSITIONS (row, col) in the 28x31 grid
# Row 24 cols 27-30, then rows 25-27 all cols
# ============================================================
k4_positions = []
for c in range(27, 31):
    k4_positions.append((24, c))
for r in range(25, 28):
    for c in range(31):
        k4_positions.append((r, c))
assert len(k4_positions) == 97

# Verify K4 matches carved text
k4_from_grid = ''.join(CIPHER_ROWS[r][c] for r, c in k4_positions)
assert k4_from_grid == K4_CARVED, f"K4 mismatch"

# K4 index -> (row, col) lookup
k4_idx_to_pos = {i: k4_positions[i] for i in range(97)}
k4_pos_to_idx = {pos: i for i, pos in enumerate(k4_positions)}

# ============================================================
# K3 POSITIONS (rows 14-23 full + row 24 cols 0-25)
# 310 + 26 = 336 positions
# ============================================================
k3_positions = []
for r in range(14, 24):
    for c in range(31):
        k3_positions.append((r, c))
for c in range(26):
    k3_positions.append((24, c))
assert len(k3_positions) == 336

k3_ct = ''.join(CIPHER_ROWS[r][c] for r, c in k3_positions)
assert len(k3_ct) == 336

# K3 known PT (from double rotational transposition solution)
K3_PT = ('SLOWLYDESPERATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISFOUNDONTHEMORNINGOFTHESEVENTEENTH'
         'ABQUESTIONSUPONCLEARLYINSCRIBEDINTHERIVERBANKVERYQUITEUNDERSTANDSTHEBOTTOMOFMY')
# Trim/pad to 336 — we only have the famous ~88-char answer; fill rest for crib checking
K3_PT_KNOWN = 'SLOWLYDESPERATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISFOUNDONTHEMORNINGOFTHESEVENTEENTH'

# ============================================================
# QUADGRAM SCORER
# ============================================================
def load_quadgrams(path='data/english_quadgrams.json'):
    try:
        with open(path) as f:
            qg = json.load(f)
        # Quadgrams are already log10 probabilities (negative floats)
        # Detect: if values look like log-probs (all negative, range -3 to -8)
        sample_vals = list(qg.values())[:10]
        if all(v < 0 for v in sample_vals):
            # Already log-probs
            floor = min(qg.values()) - 1.0   # worse than worst known quadgram
            def score(text):
                t = ''.join(c for c in text.upper() if c in AZ)
                if len(t) < 4:
                    return -99.0
                s = sum(qg.get(t[i:i+4], floor) for i in range(len(t) - 3))
                return s / (len(t) - 3)
        else:
            # Raw counts — normalise
            total = sum(qg.values())
            floor = math.log10(0.5 / total)
            log_qg = {k: math.log10(v / total) for k, v in qg.items()}
            def score(text):
                t = ''.join(c for c in text.upper() if c in AZ)
                if len(t) < 4:
                    return -99.0
                s = sum(log_qg.get(t[i:i+4], floor) for i in range(len(t) - 3))
                return s / (len(t) - 3)
        return score
    except Exception as e:
        print(f"  [quadgram load failed: {e}, using fallback IC scorer]")
        def score(text):
            t = ''.join(c for c in text.upper() if c in AZ)
            if len(t) < 2:
                return -99.0
            freq = Counter(t)
            n = len(t)
            ic = sum(v * (v - 1) for v in freq.values()) / (n * (n - 1)) if n > 1 else 0
            return (ic - 0.038) * 10   # positive when IC > 0.038
        return score

score_text = load_quadgrams()

# ============================================================
# DECRYPTION HELPERS
# ============================================================
def vig_decrypt(ct, key):
    result, ki = [], 0
    for c in ct:
        if c in AZ:
            shift = AZ.index(key[ki % len(key)])
            result.append(AZ[(AZ.index(c) - shift) % 26])
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

def beau_decrypt(ct, key):
    """Beaufort: pt = (key_idx - ct_idx) mod 26"""
    result, ki = [], 0
    for c in ct:
        if c in AZ:
            shift = AZ.index(key[ki % len(key)])
            result.append(AZ[(shift - AZ.index(c)) % 26])
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

def ka_vig_decrypt(ct, key):
    """KA-alphabet Vigenère: uses KA for both PT and key lookup"""
    result, ki = [], 0
    for c in ct:
        if c in KA:
            k_pos = KA.index(key[ki % len(key)]) if key[ki % len(key)] in KA else AZ.index(key[ki % len(key)])
            c_pos = KA.index(c)
            result.append(KA[(c_pos - k_pos) % 26])
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

CRIBS = [('EASTNORTHEAST', 21), ('BERLINCLOCK', 63)]

def check_cribs(pt):
    hits = []
    for crib, pos in CRIBS:
        if pt[pos:pos+len(crib)] == crib:
            hits.append(f"{crib}@{pos}")
        if crib in pt:
            hits.append(f"{crib}@any({pt.index(crib)})")
    return list(set(hits))

def try_all_decryptions(ct_str, label='', verbose=False):
    """Try Vig+Beau with all keywords; return sorted results."""
    best = []
    ct_alpha = ''.join(c for c in ct_str if c in AZ)
    if len(ct_alpha) < 5:
        return []
    for kw in KEYWORDS:
        kw_az = ''.join(c for c in kw if c in AZ)
        if not kw_az:
            continue
        for fn, fname in [(vig_decrypt, 'Vig'), (beau_decrypt, 'Beau')]:
            pt = fn(ct_alpha, kw_az)
            sc = score_text(pt)
            cribs = check_cribs(pt)
            if cribs:
                print(f"\n  *** CRIB HIT [{label}] {fname}({kw}): {cribs}")
                print(f"      PT: {pt}")
            best.append((sc, pt, f"{fname}({kw})"))
    best.sort(reverse=True)
    if verbose and best:
        print(f"  Best [{label}]: {best[0][0]:.4f} via {best[0][2]} => {best[0][1][:50]}")
    return best

# ============================================================
# UTILITY: describe mask stats for K4
# ============================================================
all_results = []   # (score, label, method, pt)

def analyze_mask(mask_name, hole_positions_k4):
    """Core analysis: given list of (r,c) holes in K4 region, test all decryptions."""
    n = len(hole_positions_k4)
    if n == 0:
        return
    # Tableau letters at holes
    tab_letters = ''.join(tableau[r][c] for r, c in hole_positions_k4 if tableau[r][c] in AZ)
    # Cipher letters at holes
    cip_letters = ''.join(CIPHER_ROWS[r][c] for r, c in hole_positions_k4 if CIPHER_ROWS[r][c] in AZ)

    sc_tab_raw = score_text(tab_letters)
    sc_cip_raw = score_text(cip_letters)

    # Decrypt tableau letters with all keywords
    res_tab = try_all_decryptions(tab_letters, label=f"{mask_name}/tab")
    res_cip = try_all_decryptions(cip_letters, label=f"{mask_name}/cip")

    best_tab = res_tab[0] if res_tab else (-99, '', '')
    best_cip = res_cip[0] if res_cip else (-99, '', '')

    best_score = max(best_tab[0], best_cip[0])
    all_results.append((best_score, mask_name, best_tab if best_tab[0] >= best_cip[0] else best_cip))

    print(f"  {mask_name:<40} holes={n:3d} | tab_raw={sc_tab_raw:.3f} best_tab={best_tab[0]:.3f} | cip_raw={sc_cip_raw:.3f} best_cip={best_cip[0]:.3f}")
    if best_tab[0] > -5.5:
        print(f"    Tab best: {best_tab[2]} => {best_tab[1][:60]}")
    if best_cip[0] > -5.5:
        print(f"    Cip best: {best_cip[2]} => {best_cip[1][:60]}")

# ============================================================
# APPROACH A: Cipher letter cycle membership = mask
# ============================================================
print("\n" + "="*70)
print("APPROACH A: CIPHER LETTER CYCLE MEMBERSHIP")
print("="*70)

for hole_cycle, hole_set, cycle_label in [
    (17, cycle_17, '17-cycle'),
    (8,  cycle_8,  ' 8-cycle'),
]:
    holes = [(r, c) for r, c in k4_positions if CIPHER_ROWS[r][c] in hole_set]
    analyze_mask(f"A_{cycle_label}=hole", holes)

# Also: Z excluded or included?
holes_17_plus_z = [(r, c) for r, c in k4_positions
                   if CIPHER_ROWS[r][c] in cycle_17 or CIPHER_ROWS[r][c] in cycle_1]
holes_8_plus_z  = [(r, c) for r, c in k4_positions
                   if CIPHER_ROWS[r][c] in cycle_8 or CIPHER_ROWS[r][c] in cycle_1]
analyze_mask("A_17+Z=hole", holes_17_plus_z)
analyze_mask("A_8+Z=hole",  holes_8_plus_z)

# ============================================================
# APPROACH D: Tableau letter cycle membership = mask
# ============================================================
print("\n" + "="*70)
print("APPROACH D: TABLEAU LETTER CYCLE MEMBERSHIP")
print("="*70)

for hole_cycle, hole_set, cycle_label in [
    (17, cycle_17, '17-cycle'),
    (8,  cycle_8,  ' 8-cycle'),
]:
    holes_d = [(r, c) for r, c in k4_positions if tableau[r][c] in hole_set]
    analyze_mask(f"D_{cycle_label}=hole", holes_d)

# ============================================================
# APPROACH B: Cycle index parity
# ============================================================
print("\n" + "="*70)
print("APPROACH B: CYCLE INDEX PARITY (cipher / tableau)")
print("="*70)

for src_name, src_fn in [('cipher', lambda r, c: CIPHER_ROWS[r][c]),
                          ('tableau', lambda r, c: tableau[r][c])]:
    for parity in [0, 1]:
        holes_b = [(r, c) for r, c in k4_positions
                   if src_fn(r, c) in AZ and letter_cycle_idx[src_fn(r, c)] % 2 == parity]
        analyze_mask(f"B_{src_name}_idx%2=={parity}", holes_b)

# Also: cycle_idx mod 3 variants
for src_name, src_fn in [('cipher', lambda r, c: CIPHER_ROWS[r][c])]:
    for mod3 in [0, 1, 2]:
        holes_b3 = [(r, c) for r, c in k4_positions
                    if src_fn(r, c) in AZ and letter_cycle_idx[src_fn(r, c)] % 3 == mod3]
        analyze_mask(f"B_{src_name}_idx%3=={mod3}", holes_b3)

# ============================================================
# APPROACH C: Apply perm N times, then check cycle membership
# ============================================================
print("\n" + "="*70)
print("APPROACH C: APPLY PERM^N TO CIPHER LETTER, CHECK MEMBERSHIP")
print("="*70)

def perm_n(letter, n):
    n = n % 136  # order = LCM(17,8) = 136
    for _ in range(n):
        letter = perm[letter]
    return letter

for n in [1, 2, 3, 4, 7, 8, 9, 16, 17, 25, 34]:
    for hole_set, set_label in [(cycle_17, '17'), (cycle_8, '8')]:
        holes_c = [(r, c) for r, c in k4_positions
                   if CIPHER_ROWS[r][c] in AZ and perm_n(CIPHER_ROWS[r][c], n) in hole_set]
        if len(holes_c) not in (0, 97):  # only print interesting ones
            analyze_mask(f"C_perm^{n}_{set_label}=hole", holes_c)

# ============================================================
# APPROACH E: Row / Column key cycle membership -> row/col rule
# ============================================================
print("\n" + "="*70)
print("APPROACH E: ROW/COL KEY CYCLE MEMBERSHIP")
print("="*70)

def row_key(r):
    """Key letter for row r: AZ[r-1] for r=1..26, else None"""
    if 1 <= r <= 26:
        return AZ[r - 1]
    return None

def col_header(c):
    """Header letter for col c: AZ[(c-1)%26] for c=1..30, else None"""
    if 1 <= c <= 30:
        return AZ[(c - 1) % 26]
    return None  # c==0 is key column slot

# E1: entire row is a hole if row key is in cycle_17 (or cycle_8)
for hole_set, set_label in [(cycle_17, '17'), (cycle_8, '8')]:
    holes_e1 = [(r, c) for r, c in k4_positions
                if row_key(r) is not None and row_key(r) in hole_set]
    analyze_mask(f"E1_row_{set_label}=hole", holes_e1)

# E2: entire col is a hole if col header is in cycle_17 (or cycle_8)
for hole_set, set_label in [(cycle_17, '17'), (cycle_8, '8')]:
    holes_e2 = [(r, c) for r, c in k4_positions
                if col_header(c) is not None and col_header(c) in hole_set]
    analyze_mask(f"E2_col_{set_label}=hole", holes_e2)

# E3: hole if BOTH row key and col header are in the SAME cycle
# Case: both in 17
holes_same17 = [(r, c) for r, c in k4_positions
                if row_key(r) in cycle_17 and col_header(c) in cycle_17]
analyze_mask("E3_row17_AND_col17", holes_same17)

# Case: both in 8
holes_same8 = [(r, c) for r, c in k4_positions
               if row_key(r) in cycle_8 and col_header(c) in cycle_8]
analyze_mask("E3_row8_AND_col8", holes_same8)

# E4: hole if row key and col header are in DIFFERENT cycles (XOR)
holes_xor = [(r, c) for r, c in k4_positions
             if row_key(r) is not None and col_header(c) is not None
             and row_key(r) in AZ and col_header(c) in AZ
             and (row_key(r) in cycle_17) != (col_header(c) in cycle_17)]
analyze_mask("E4_row_XOR_col_cycle", holes_xor)

# E5: hole if EITHER row key OR col header is in cycle_17 (OR)
holes_or17 = [(r, c) for r, c in k4_positions
              if (row_key(r) is not None and row_key(r) in cycle_17)
              or (col_header(c) is not None and col_header(c) in cycle_17)]
analyze_mask("E5_row_OR_col_in_17", holes_or17)

# ============================================================
# APPROACH F: KA-index difference (cipher - tableau) mod 26
# ============================================================
print("\n" + "="*70)
print("APPROACH F: CIPHER-TABLEAU KA-INDEX DIFFERENCE -> CYCLE")
print("="*70)

def ka_diff_letter(r, c):
    """Returns AZ[diff] where diff = (KA_idx(cipher) - KA_idx(tableau)) % 26"""
    cip = CIPHER_ROWS[r][c]
    tab = tableau[r][c]
    if cip not in KA or tab not in KA:
        return None
    diff = (KA.index(cip) - KA.index(tab)) % 26
    return AZ[diff]   # interpret diff as AZ index -> AZ letter

for hole_set, set_label in [(cycle_17, '17'), (cycle_8, '8')]:
    holes_f = [(r, c) for r, c in k4_positions
               if ka_diff_letter(r, c) is not None and ka_diff_letter(r, c) in hole_set]
    analyze_mask(f"F_KAdiff_{set_label}=hole", holes_f)

# Also: AZ-index difference
def az_diff_letter(r, c):
    cip = CIPHER_ROWS[r][c]
    tab = tableau[r][c]
    if cip not in AZ or tab not in AZ:
        return None
    diff = (AZ.index(cip) - AZ.index(tab)) % 26
    return AZ[diff]

for hole_set, set_label in [(cycle_17, '17'), (cycle_8, '8')]:
    holes_f2 = [(r, c) for r, c in k4_positions
                if az_diff_letter(r, c) is not None and az_diff_letter(r, c) in hole_set]
    analyze_mask(f"F_AZdiff_{set_label}=hole", holes_f2)

# ============================================================
# APPROACH P: PERMUTATION REORDERING of K4 by cycle structure
# ============================================================
print("\n" + "="*70)
print("APPROACH P: CYCLE-INDEX REORDERING OF K4 (descramble)")
print("="*70)

# The 97 K4 characters are in cycles with specific indices.
# If the cycle index within each cycle tells you the TRUE order,
# we can reconstruct the original ciphertext ordering.

# P1: Sort K4 positions by (cycle_size DESC, cycle_idx ASC, k4_position ASC)
#     => 17-cycle letters first (sorted by idx), then 8-cycle, then Z
def sort_key_p1(i):
    ch = K4_CARVED[i]
    if ch not in AZ:
        return (3, 0, i)   # Z or ? goes last
    sz = letter_cycle_size[ch]
    idx = letter_cycle_idx[ch]
    group = 0 if sz == 17 else (1 if sz == 8 else 2)
    return (group, idx, i)

perm_p1 = sorted(range(97), key=sort_key_p1)
k4_reordered_p1 = ''.join(K4_CARVED[i] for i in perm_p1)
sc_p1 = score_text(k4_reordered_p1)
print(f"\nP1 (17-cycle first, by idx): score={sc_p1:.4f}")
print(f"  Reordered: {k4_reordered_p1}")
res_p1 = try_all_decryptions(k4_reordered_p1, label="P1")
if res_p1:
    print(f"  Best decrypt: {res_p1[0][0]:.4f} {res_p1[0][2]} => {res_p1[0][1][:60]}")
all_results.append((res_p1[0][0] if res_p1 else sc_p1, "P1_reorder", res_p1[0] if res_p1 else (-99, '', '')))

# P2: Sort by (cycle_size ASC, cycle_idx ASC) => 8-cycle first
def sort_key_p2(i):
    ch = K4_CARVED[i]
    if ch not in AZ:
        return (3, 0, i)
    sz = letter_cycle_size[ch]
    idx = letter_cycle_idx[ch]
    group = 1 if sz == 17 else (0 if sz == 8 else 2)
    return (group, idx, i)

perm_p2 = sorted(range(97), key=sort_key_p2)
k4_reordered_p2 = ''.join(K4_CARVED[i] for i in perm_p2)
sc_p2 = score_text(k4_reordered_p2)
print(f"\nP2 (8-cycle first, by idx): score={sc_p2:.4f}")
res_p2 = try_all_decryptions(k4_reordered_p2, label="P2")
if res_p2:
    print(f"  Best decrypt: {res_p2[0][0]:.4f} {res_p2[0][2]} => {res_p2[0][1][:60]}")
all_results.append((res_p2[0][0] if res_p2 else sc_p2, "P2_reorder", res_p2[0] if res_p2 else (-99, '', '')))

# P3: Sort by cycle_idx only (within each cycle), interleaved
# Map each K4 position to cycle_idx, then sort by cycle_idx as primary key
def sort_key_p3(i):
    ch = K4_CARVED[i]
    if ch not in AZ:
        return (99, i)
    return (letter_cycle_idx[ch], i)

perm_p3 = sorted(range(97), key=sort_key_p3)
k4_reordered_p3 = ''.join(K4_CARVED[i] for i in perm_p3)
sc_p3 = score_text(k4_reordered_p3)
print(f"\nP3 (sort by cycle_idx only): score={sc_p3:.4f}")
res_p3 = try_all_decryptions(k4_reordered_p3, label="P3")
if res_p3:
    print(f"  Best decrypt: {res_p3[0][0]:.4f} {res_p3[0][2]} => {res_p3[0][1][:60]}")

# P4: Apply AZ->KA permutation to each K4 letter, try decrypt
k4_permuted = ''.join(perm.get(ch, ch) for ch in K4_CARVED)
print(f"\nP4 (apply perm to each K4 letter): {k4_permuted}")
sc_p4 = score_text(k4_permuted)
print(f"  Score: {sc_p4:.4f}")
res_p4 = try_all_decryptions(k4_permuted, label="P4")
if res_p4:
    print(f"  Best decrypt: {res_p4[0][0]:.4f} {res_p4[0][2]} => {res_p4[0][1][:60]}")
all_results.append((res_p4[0][0] if res_p4 else sc_p4, "P4_perm_each", res_p4[0] if res_p4 else (-99, '', '')))

# P5: Apply inverse permutation (KA->AZ)
inv_perm = {v: k for k, v in perm.items()}
k4_inv_permuted = ''.join(inv_perm.get(ch, ch) for ch in K4_CARVED)
print(f"\nP5 (apply inv perm to each K4 letter): {k4_inv_permuted}")
sc_p5 = score_text(k4_inv_permuted)
print(f"  Score: {sc_p5:.4f}")
res_p5 = try_all_decryptions(k4_inv_permuted, label="P5")
if res_p5:
    print(f"  Best decrypt: {res_p5[0][0]:.4f} {res_p5[0][2]} => {res_p5[0][1][:60]}")

# ============================================================
# APPROACH R: 180-degree rotation - read partner positions
# ============================================================
print("\n" + "="*70)
print("APPROACH R: 180-DEGREE ROTATION PARTNERS")
print("="*70)

# K4 position (r,c) -> partner (27-r, 30-c) in top half
k4_partners = [(27 - r, 30 - c) for r, c in k4_positions]
partner_rows = sorted(set(r for r, c in k4_partners))
print(f"Partner rows: {partner_rows}")

# Read tableau/cipher at partner positions
partner_tab = ''.join(tableau[r][c] for r, c in k4_partners if tableau[r][c] in AZ)
partner_cip = ''.join(CIPHER_ROWS[r][c] for r, c in k4_partners if CIPHER_ROWS[r][c] in AZ)

sc_ptab = score_text(partner_tab)
sc_pcip = score_text(partner_cip)
print(f"Partner tableau letters: {partner_tab}")
print(f"  Score: {sc_ptab:.4f}")
print(f"Partner cipher letters:  {partner_cip}")
print(f"  Score: {sc_pcip:.4f}")

res_ptab = try_all_decryptions(partner_tab, label="R_tab")
res_pcip = try_all_decryptions(partner_cip, label="R_cip")
if res_ptab:
    print(f"  Partner tab best: {res_ptab[0][0]:.4f} {res_ptab[0][2]} => {res_ptab[0][1][:60]}")
if res_pcip:
    print(f"  Partner cip best: {res_pcip[0][0]:.4f} {res_pcip[0][2]} => {res_pcip[0][1][:60]}")
all_results.append((res_ptab[0][0] if res_ptab else sc_ptab, "R_tab", res_ptab[0] if res_ptab else (-99, '', '')))
all_results.append((res_pcip[0][0] if res_pcip else sc_pcip, "R_cip", res_pcip[0] if res_pcip else (-99, '', '')))

# Also try: 17-cycle holes among PARTNERS, read their cipher letters
for hole_set, set_label in [(cycle_17, '17'), (cycle_8, '8')]:
    holes_r = [(r, c) for r, c in k4_partners if CIPHER_ROWS[r][c] in hole_set]
    tab_here = ''.join(tableau[r][c] for r, c in holes_r if tableau[r][c] in AZ)
    cip_here = ''.join(CIPHER_ROWS[r][c] for r, c in holes_r if CIPHER_ROWS[r][c] in AZ)
    sc_t = score_text(tab_here)
    sc_c = score_text(cip_here)
    print(f"\nR_partner_{set_label}=hole: {len(holes_r)}/97 holes")
    print(f"  partner-tab: {tab_here[:40]} (score={sc_t:.3f})")
    print(f"  partner-cip: {cip_here[:40]} (score={sc_c:.3f})")

# ============================================================
# APPROACH G: K3 REGION VERIFICATION
# ============================================================
print("\n" + "="*70)
print("APPROACH G: K3 REGION VERIFICATION")
print("="*70)

# Apply approach A to K3: 17-cycle holes -> read tableau letters -> decrypt with ABSCISSA
for hole_set, set_label in [(cycle_17, '17'), (cycle_8, '8')]:
    k3_holes = [(r, c) for r, c in k3_positions
                if CIPHER_ROWS[r][c] in hole_set]
    k3_tab = ''.join(tableau[r][c] for r, c in k3_holes if tableau[r][c] in AZ)
    k3_cip = ''.join(CIPHER_ROWS[r][c] for r, c in k3_holes if CIPHER_ROWS[r][c] in AZ)

    # Decrypt with ABSCISSA (known K3 key)
    k3_dec_abscissa = vig_decrypt(k3_tab, 'ABSCISSA')
    k3_dec_shadow   = vig_decrypt(k3_tab, 'SHADOW')
    k3_dec_raw_sc   = score_text(k3_tab)
    k3_dec_sc       = score_text(k3_dec_abscissa)

    print(f"\nG_K3_{set_label}=hole: {len(k3_holes)}/336 holes")
    print(f"  K3 tab raw:         {k3_tab[:50]}... (score={k3_dec_raw_sc:.3f})")
    print(f"  Vig(ABSCISSA) =>    {k3_dec_abscissa[:50]}... (score={k3_dec_sc:.3f})")
    print(f"  K3 PT starts with:  {K3_PT_KNOWN[:30]}")
    print(f"  Contains K3 crib:   {'SLOWLYDESPERATLY' in k3_dec_abscissa}")

# ============================================================
# SPECIAL: SELF-ENCRYPTING POSITIONS
# ============================================================
print("\n" + "="*70)
print("SPECIAL: SELF-ENCRYPTING POSITIONS & MATCH POSITIONS")
print("="*70)

# CT=PT at K4[32]=S and K4[73]=K
se_positions = [(32, 'S'), (73, 'K')]
for k4_idx, expected_letter in se_positions:
    r, c = k4_positions[k4_idx]
    cip = CIPHER_ROWS[r][c]
    tab = tableau[r][c]
    cip_cycle = f"{letter_cycle_size.get(cip, '?')}-cycle[{letter_cycle_idx.get(cip, '?')}]"
    tab_cycle = f"{letter_cycle_size.get(tab, '?')}-cycle[{letter_cycle_idx.get(tab, '?')}]" if tab in AZ else 'blank'
    print(f"K4[{k4_idx}]={cip} at ({r},{c}): cipher_cycle={cip_cycle}, tableau={tab} ({tab_cycle})")

# All positions where cipher == tableau in K4
match_k4 = [(r, c) for r, c in k4_positions if CIPHER_ROWS[r][c] == tableau[r][c] and CIPHER_ROWS[r][c] in AZ]
print(f"\nK4 positions where cipher==tableau: {len(match_k4)}")
for r, c in match_k4:
    letter = CIPHER_ROWS[r][c]
    idx_k4 = k4_pos_to_idx[(r, c)]
    print(f"  ({r},{c}) = {letter} [K4 idx {idx_k4}], cycle={letter_cycle_size[letter]}-cycle[{letter_cycle_idx[letter]}]")

# All cipher==tableau in full grid
all_match = [(r, c) for r in range(28) for c in range(31)
             if CIPHER_ROWS[r][c] == tableau[r][c] and CIPHER_ROWS[r][c] in AZ]
print(f"\nFull grid cipher==tableau positions: {len(all_match)}")

# ============================================================
# APPROACH H: COMBINED ROW+COL CYCLE LOGIC (TABLEAU-BASED)
# Tableau has row key letter and body letters.
# A cell (r,c) can have: row key in cycle X, col position in cycle Y
# ============================================================
print("\n" + "="*70)
print("APPROACH H: ROW KEY XOR COL HEADER CYCLE (TABLEAU-BASED MASK)")
print("="*70)

# For the tableau: the cell (r,c) is determined by row key AZ[r-1] and col pt AZ[(c-1)%26]
# These are independent indicators. Test all combinations.

for row_set, row_label in [(cycle_17, '17'), (cycle_8, '8')]:
    for col_set, col_label in [(cycle_17, '17'), (cycle_8, '8')]:
        for logic, logic_label in [
            (lambda rk, ck: rk and ck, 'AND'),
            (lambda rk, ck: rk or ck, 'OR'),
            (lambda rk, ck: rk != ck, 'XOR'),
        ]:
            holes_h = [(r, c) for r, c in k4_positions
                       if row_key(r) is not None and col_header(c) is not None
                       and logic(row_key(r) in row_set, col_header(c) in col_set)]
            if 5 < len(holes_h) < 95:
                analyze_mask(f"H_row{row_label}_{logic_label}_col{col_label}", holes_h)

# ============================================================
# FINAL SUMMARY
# ============================================================
print("\n" + "="*70)
print("FINAL SUMMARY — TOP 20 RESULTS BY SCORE")
print("="*70)

all_results.sort(key=lambda x: -x[0])
print(f"{'Score':>8} {'Mask':<45} {'Method':<25} {'PT snippet'}")
print("-" * 120)
for score, mask, res in all_results[:20]:
    pt_snippet = res[1][:55] if isinstance(res, tuple) and len(res) > 1 else ''
    method = res[2] if isinstance(res, tuple) and len(res) > 2 else ''
    print(f"{score:>8.4f} {mask:<45} {method:<25} {pt_snippet}")

best_score = all_results[0][0] if all_results else -99
best_mask  = all_results[0][1] if all_results else 'none'
best_res   = all_results[0][2] if all_results else ('', '', '')
print(f"\n=== WINNER: {best_mask} score={best_score:.4f} ===")
if isinstance(best_res, tuple) and len(best_res) > 1:
    print(f"Method: {best_res[2]}")
    print(f"PT:     {best_res[1]}")
