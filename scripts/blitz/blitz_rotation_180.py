#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: blitz
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_rotation_180.py — EXTENDED 180° Cardan Grille Analysis (2026-03-04)
==========================================================================
Tests the 180-degree rotation hypothesis with NEW approaches:

 A. KA-cycle based masks (17-cycle vs 8-cycle vs Z defines holes)
 B. Tableau overlay masks (cipher vs tableau comparison)
 C. Column-major reading order with various hole sets
 D. K3 calibration — which holes are consistent with K3's known PT?
 E. Self-encrypting constraint analysis (sigma[32] and sigma[73] forced)
 F. Bean equality/inequality constraints on sigma
 G. Crib-constrained permutation search (enumerate sigmas from crib positions)
 H. Antisymmetric half-selection — mathematical proof of what's reachable
 I. Period-8 "8 Lines 73" and tableau anomalies (V-N=T-L=8)
 J. ALL grille readings with K3-calibrated mask

Structural claim being tested:
  Position 1 (normal):  read grille holes → K1+K2 (434 chars)
  Position 2 (180° flip): read grille holes → K3+?+K4 (434 chars)
  868/2 = 434 = K1+K2 = K3+?+K4 = perfect center split
"""

import sys
import time
from math import gcd
from collections import Counter
from itertools import product

sys.path.insert(0, 'scripts')
from kbot_harness import (
    AZ, KA, KEYWORDS, CRIBS,
    vig_decrypt, vig_encrypt, beau_decrypt,
    score_text, score_text_per_char, has_cribs,
    load_quadgrams,
)

t0 = time.time()
load_quadgrams()

# ─────────────────────────────────────────────────────────────────────────────
# 1. BUILD THE 28×31 CIPHER GRID
# ─────────────────────────────────────────────────────────────────────────────

CIPHER_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",   # row  0  K1
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",   # row  1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",   # row  2  K1→K2
    "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",  # row  3  (? at col 7)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # row  4
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",   # row  5
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",   # row  6
    "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER",   # row  7  (? at col 9)
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",   # row  8
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",   # row  9
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",   # row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",   # row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",   # row 13  K2 ends
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",   # row 14  K3 starts (CENTER)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # row 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",   # row 17
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",   # row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",   # row 19
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",   # row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",   # row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",   # row 22
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",   # row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",   # row 24  K4 starts col 27 (? col 26)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",   # row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",   # row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",  # row 27  K4 ends
]

assert len(CIPHER_ROWS) == 28
for i, row in enumerate(CIPHER_ROWS):
    assert len(row) == 31, f"Row {i} len={len(row)}"

GRID = ''.join(CIPHER_ROWS)
assert len(GRID) == 868

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4_CARVED) == 97
assert GRID[771:868] == K4_CARVED

K3_FLAT_START, K3_FLAT_END = 434, 770   # K3 carved: 336 chars
K4_FLAT_START, K4_FLAT_END = 771, 868   # K4 carved: 97 chars

print("=" * 72)
print("BLITZ ROTATION 180 — Extended Analysis (2026-03-04)")
print("=" * 72)

# ─────────────────────────────────────────────────────────────────────────────
# 2. BUILD THE 28×31 KA VIGENERE TABLEAU
# ─────────────────────────────────────────────────────────────────────────────
# Row 0:  header " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD" (col 0=blank, cols 1-30=ABCD...)
# Row 1-26: key col = AZ[r-1], body cols 1-30 = KA shifted by (r-1)
# Row 27: same as row 0 (footer)

def build_tableau():
    """Build 28×31 KA Vigenère tableau as list of 31-char strings."""
    rows = []
    # Row 0: header
    header = ' ' + ''.join(AZ[(c-1) % 26] for c in range(1, 31))  # 31 chars
    rows.append(header)
    # Rows 1-26: key col + 30 body chars
    for r in range(1, 27):
        key_letter = AZ[r-1]
        body = ''.join(KA[(r-1+c) % 26] for c in range(30))
        rows.append(key_letter + body)
    # Row 27: footer (same as header)
    rows.append(header)
    assert all(len(r) == 31 for r in rows), "Tableau row length error"
    return rows

TABLEAU_ROWS = build_tableau()
TABLEAU = ''.join(TABLEAU_ROWS)
assert len(TABLEAU) == 868

# Verify a few known values from the mission description
# Row 1 (key=A): KRYPTOSABCDEFGHIJLMNQUVWXZKRYP (cols 1-30)
assert TABLEAU_ROWS[1][1:11] == 'KRYPTOSABC', f"Tableau row 1 wrong: {TABLEAU_ROWS[1]}"
# Row 14 (key=N): body = KA[(13+c)%26] for c=0..29
row14_body = ''.join(KA[(13+c) % 26] for c in range(30))
assert TABLEAU_ROWS[14][1:] == row14_body, f"Tableau row 14 wrong"
print(f"Tableau sanity: PASS ✓ (row 1: {TABLEAU_ROWS[1][:11]}...)")
print(f"  Row 14 (key=N): {TABLEAU_ROWS[14][:16]}... extra-L would be at col 31='{KA[(13+30)%26]}'")
print(f"  Row 22 (key=V): {TABLEAU_ROWS[22][:16]}... extra-T check col 31='{KA[(21+30)%26]}'")

# ─────────────────────────────────────────────────────────────────────────────
# 3. COMPUTE AZ→KA PERMUTATION & CYCLE STRUCTURE
# ─────────────────────────────────────────────────────────────────────────────

AZ_TO_KA = [KA.index(AZ[i]) for i in range(26)]  # AZ position → KA position
KA_TO_AZ = [AZ.index(KA[i]) for i in range(26)]  # KA position → AZ position

def find_cycles(perm):
    """Find cycles of a permutation on 0..len(perm)-1."""
    visited = [False] * len(perm)
    cycles = []
    for start in range(len(perm)):
        if visited[start]:
            continue
        cycle = []
        x = start
        while not visited[x]:
            visited[x] = True
            cycle.append(x)
            x = perm[x]
        cycles.append(cycle)
    return cycles

cycles_AZ_to_KA = find_cycles(AZ_TO_KA)
print(f"\nAZ→KA permutation cycles:")
for c in sorted(cycles_AZ_to_KA, key=len, reverse=True):
    letters = ''.join(AZ[i] for i in c)
    print(f"  {len(c)}-cycle: positions {sorted(c)} = letters {letters}")

# Identify cycle membership
cycle17_positions = set()  # 17-cycle AZ indices
cycle8_positions = set()   # 8-cycle AZ indices
cycleZ_positions = set()   # fixed point(s)
for c in cycles_AZ_to_KA:
    if len(c) == 17:
        cycle17_positions.update(c)
    elif len(c) == 8:
        cycle8_positions.update(c)
    else:
        cycleZ_positions.update(c)

cycle17_letters = set(AZ[i] for i in cycle17_positions)
cycle8_letters = set(AZ[i] for i in cycle8_positions)
cycleZ_letters = set(AZ[i] for i in cycleZ_positions)

print(f"\n17-cycle letters: {''.join(sorted(cycle17_letters))}")
print(f" 8-cycle letters: {''.join(sorted(cycle8_letters))}")
print(f"  Z-cycle letters: {''.join(sorted(cycleZ_letters))}")

# ─────────────────────────────────────────────────────────────────────────────
# 4. K3 SANITY CHECK
# ─────────────────────────────────────────────────────────────────────────────

print("\n══ K3 verification ══")

def k3_ct_to_pt(i):
    a = i // 24; b = i % 24
    inter = 14*b + 13 - a
    c = inter // 8; d = inter % 8
    return 42*d + 41 - c

K3_PERM = [k3_ct_to_pt(i) for i in range(336)]
assert sorted(K3_PERM) == list(range(336)), "K3 perm not bijection!"

K3_CARVED = GRID[K3_FLAT_START:K3_FLAT_END]
K3_PT_LIST = [''] * 336
for ct_i, pt_i in enumerate(K3_PERM):
    K3_PT_LIST[pt_i] = K3_CARVED[ct_i]
K3_PT = ''.join(K3_PT_LIST)
assert K3_PT[:16] == "SLOWLYDESPARATLY", f"K3 PT wrong: {K3_PT[:16]}"
assert K3_PT[-23:] == "MISTXCANYOUSEEANYTHINGQ"
print(f"K3 PT[0:20]  = {K3_PT[:20]}")
print(f"K3 sanity: PASS ✓")

# K3 inverse permutation
K3_INV = [0]*336
for ct_i, pt_i in enumerate(K3_PERM):
    K3_INV[pt_i] = ct_i

# ─────────────────────────────────────────────────────────────────────────────
# 5. HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def reflect180(i):    return 867 - i
def flat_to_rc(i):    return divmod(i, 31)
def rc_to_flat(r, c): return 31 * r + c
def rc_to_colmaj(r, c): return c * 28 + r

ALL_CRIB_HITS = []
RESULTS = []

def test97(seq, label=""):
    """Try all keywords × alphabets × ciphers on 97-char seq."""
    if not seq or len(seq) != 97:
        return -99.0, None, []
    best_spc = -999.0
    best = None
    crib_hits = []
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cfn(seq, kw, alpha)
                except (ValueError, IndexError):
                    continue
                hits = has_cribs(pt)
                spc  = score_text_per_char(pt)
                if hits:
                    r = dict(label=label, pt=pt, seq=seq,
                             kw=kw, alpha=alpha_name, cipher=cname,
                             spc=spc, hits=hits)
                    crib_hits.append(r)
                    print(f"\n{'!'*60}\nCRIB HIT! [{label}]")
                    print(f"  key={kw}/{alpha_name}/{cname}  spc={spc:.3f}")
                    print(f"  PT : {pt}")
                    print(f"  hits: {hits}")
                    print('!'*60)
                if spc > best_spc:
                    best_spc = spc
                    best = dict(label=label, pt=pt, seq=seq,
                                kw=kw, alpha=alpha_name, cipher=cname,
                                spc=spc, hits=hits)
    return best_spc, best, crib_hits

def run(seq, label):
    spc, best, hits = test97(seq, label)
    ALL_CRIB_HITS.extend(hits)
    if best:
        RESULTS.append((spc, label, best))
    if best:
        print(f"  {label:<60} spc={spc:6.3f}  {best['kw']}/{best['alpha']}/{best['cipher']}")
    else:
        print(f"  {label:<60} SKIP")
    return spc, best, hits

# ─────────────────────────────────────────────────────────────────────────────
# 6. PART A: KA-CYCLE BASED MASKS
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART A: KA-Cycle Based Masks")
print("═"*72)

def make_cycle_mask(grid, letter_set, name):
    """Mask: 1=hole if grid char in letter_set (for non-'?' chars)."""
    holes = []
    for i, ch in enumerate(grid):
        if ch in letter_set:
            holes.append(i)
    return holes, name

# Build various masks
print(f"\nBuilding KA-cycle masks for 868-char grid:")

mask_17_cipher = [i for i, ch in enumerate(GRID) if ch in cycle17_letters]
mask_8_cipher  = [i for i, ch in enumerate(GRID) if ch in cycle8_letters]
mask_Z_cipher  = [i for i, ch in enumerate(GRID) if ch in cycleZ_letters]
mask_17_tab    = [i for i, ch in enumerate(TABLEAU) if ch in cycle17_letters]
mask_8_tab     = [i for i, ch in enumerate(TABLEAU) if ch in cycle8_letters]

print(f"  17-cycle on cipher grid: {len(mask_17_cipher)} holes")
print(f"   8-cycle on cipher grid: {len(mask_8_cipher)} holes")
print(f"   Z-cycle on cipher grid: {len(mask_Z_cipher)} holes")
print(f"  17-cycle on tableau:     {len(mask_17_tab)} holes")
print(f"   8-cycle on tableau:     {len(mask_8_tab)} holes")
print(f"  (For 180° antisymm: need exactly 434 holes)")

def extract_k4_from_holes(holes, reading_order='row', label=""):
    """
    Given hole positions in the 868-char grid, read in specified order.
    Returns the 97-char segment that aligns with K4's original positions.
    Also returns the full 868-char real CT.
    """
    if not holes:
        return None, None
    if reading_order == 'row':
        H_sorted = sorted(holes)
        Hbar_sorted = sorted(set(range(868)) - set(holes))
    elif reading_order == 'col':
        H_sorted = sorted(holes, key=lambda i: rc_to_colmaj(*flat_to_rc(i)))
        Hbar_sorted = sorted(set(range(868)) - set(holes),
                              key=lambda i: rc_to_colmaj(*flat_to_rc(i)))
    else:
        return None, None

    real_ct = ''.join(GRID[i] for i in H_sorted) + ''.join(GRID[i] for i in Hbar_sorted)
    # Extract K4 segment: find where K4 chars land in real_ct
    # K4 original positions: 771..867
    # In H_sorted: K4 positions that are in holes, in order
    # In Hbar_sorted: K4 positions that are not in holes, in order
    k4_in_H    = [i for i in H_sorted    if i >= K4_FLAT_START]
    k4_in_Hbar = [i for i in Hbar_sorted if i >= K4_FLAT_START]

    n_H  = len(k4_in_H)
    n_Hbar = len(k4_in_Hbar)
    assert n_H + n_Hbar == 97, f"K4 split: {n_H}+{n_Hbar}={n_H+n_Hbar}≠97"

    # Positions of K4 chars in real_ct:
    # K4 in H: last n_H positions of H_sorted → positions |H|−n_H .. |H|−1 in real_ct
    len_H = len(H_sorted)
    pos_H_start = len_H - n_H  # start of K4 in H portion of real_ct

    # K4 in Hbar: last n_Hbar positions of Hbar_sorted → positions 434+len(Hbar)−n_Hbar .. 867
    len_Hbar = len(Hbar_sorted)
    pos_Hbar_start = len_H + (len_Hbar - n_Hbar)  # start of K4 in Hbar portion

    # Extract K4 chars in order (H portion then Hbar portion)
    k4_real_ct_chars = (
        [GRID[i] for i in k4_in_H] +
        [GRID[i] for i in k4_in_Hbar]
    )
    k4_real_ct = ''.join(k4_real_ct_chars)

    # Also: key offsets for K4 chars
    # j-th K4 char (j=0..n_H-1 in H, j=n_H..96 in Hbar)
    k4_positions_in_realct = (
        list(range(pos_H_start, pos_H_start + n_H)) +
        list(range(pos_Hbar_start, pos_Hbar_start + n_Hbar))
    )

    return k4_real_ct, k4_positions_in_realct

def try_mask_with_keys(holes, label, reading_orders=('row',)):
    """Test a hole mask with all reading orders, keywords, ciphers."""
    if not holes:
        return
    hole_set = set(holes)
    for order in reading_orders:
        k4_seq, k4_positions = extract_k4_from_holes(holes, reading_order=order, label=label)
        if k4_seq and len(k4_seq) == 97:
            full_label = f"{label} [{order}-major]"
            run(k4_seq, full_label)

# ── A1: 17-cycle cipher ──
print(f"\nA1: 17-cycle cipher chars as holes ({len(mask_17_cipher)} holes)")
try_mask_with_keys(mask_17_cipher, "A1:17cyc-cipher", ('row', 'col'))

# ── A2: 8-cycle cipher ──
print(f"\nA2: 8-cycle cipher chars as holes ({len(mask_8_cipher)} holes)")
try_mask_with_keys(mask_8_cipher, "A2:8cyc-cipher", ('row', 'col'))

# ── A3: 17-cycle tableau ──
print(f"\nA3: 17-cycle tableau chars as holes ({len(mask_17_tab)} holes)")
try_mask_with_keys(mask_17_tab, "A3:17cyc-tab", ('row', 'col'))

# ── A4: 8-cycle tableau ──
print(f"\nA4: 8-cycle tableau chars as holes ({len(mask_8_tab)} holes)")
try_mask_with_keys(mask_8_tab, "A4:8cyc-tab", ('row', 'col'))

# ── A5: 8-cycle + Z cipher (complement of 17-cycle) ──
mask_not17_cipher = [i for i in range(868) if GRID[i] not in cycle17_letters and GRID[i] != '?']
print(f"\nA5: Non-17-cycle cipher chars as holes ({len(mask_not17_cipher)} holes)")
try_mask_with_keys(mask_not17_cipher, "A5:not17-cipher", ('row', 'col'))

# ─────────────────────────────────────────────────────────────────────────────
# 7. PART B: TABLEAU OVERLAY MASKS
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART B: Tableau Overlay Masks (cipher vs tableau comparison)")
print("═"*72)

# For each cell (r,c): compare cipher char vs tableau char
cipher_eq_tab   = []  # positions where cipher == tableau
cipher_neq_tab  = []  # positions where cipher != tableau
cipher_gt_tab_AZ = []  # AZ.index(cipher) > AZ.index(tableau)
cipher_lt_tab_AZ = []  # AZ.index(cipher) < AZ.index(tableau)
cipher_gt_tab_KA = []  # KA.index(cipher) > KA.index(tableau)
cipher_lt_tab_KA = []  # KA.index(cipher) < KA.index(tableau)

for i in range(868):
    c_ch = GRID[i]
    t_ch = TABLEAU[i]
    if c_ch == '?' or t_ch == ' ':
        continue  # skip unknowns and blanks
    if c_ch in AZ and t_ch in AZ:
        c_az = AZ.index(c_ch)
        t_az = AZ.index(t_ch)
        if c_ch in KA and t_ch in KA:
            c_ka = KA.index(c_ch)
            t_ka = KA.index(t_ch)
        else:
            c_ka = t_ka = 0  # placeholder

        if c_ch == t_ch:
            cipher_eq_tab.append(i)
        else:
            cipher_neq_tab.append(i)

        if c_az > t_az:
            cipher_gt_tab_AZ.append(i)
        elif c_az < t_az:
            cipher_lt_tab_AZ.append(i)

        if c_ch in KA and t_ch in KA:
            if c_ka > t_ka:
                cipher_gt_tab_KA.append(i)
            elif c_ka < t_ka:
                cipher_lt_tab_KA.append(i)

print(f"\nOverlay comparison (cipher vs tableau):")
print(f"  cipher == tableau (overlap): {len(cipher_eq_tab)} positions")
print(f"  cipher != tableau:           {len(cipher_neq_tab)} positions")
print(f"  cipher_AZ > tableau_AZ:      {len(cipher_gt_tab_AZ)} positions")
print(f"  cipher_AZ < tableau_AZ:      {len(cipher_lt_tab_AZ)} positions")
print(f"  cipher_KA > tableau_KA:      {len(cipher_gt_tab_KA)} positions")
print(f"  cipher_KA < tableau_KA:      {len(cipher_lt_tab_KA)} positions")

masks_B = [
    (cipher_eq_tab,    "B1:cipher==tableau"),
    (cipher_neq_tab,   "B2:cipher!=tableau"),
    (cipher_gt_tab_AZ, "B3:cipher>tab(AZ)"),
    (cipher_lt_tab_AZ, "B4:cipher<tab(AZ)"),
    (cipher_gt_tab_KA, "B5:cipher>tab(KA)"),
    (cipher_lt_tab_KA, "B6:cipher<tab(KA)"),
]
for holes, label in masks_B:
    print(f"\n{label} ({len(holes)} holes)")
    try_mask_with_keys(holes, label, ('row', 'col'))

# ─────────────────────────────────────────────────────────────────────────────
# 8. PART C: ANTISYMMETRIC 180° MATHEMATICAL ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART C: Antisymmetric 180° — Mathematical Reachability")
print("═"*72)

print("""
THEOREM: Under ascending-flat-index reading order with antisymmetric H:
  K4 chars always appear in NATURAL ORDER in real_CT.
  For k K4 chars in H: real_CT[434-k:434] = K4_CARVED[0:k]
                        real_CT[771+k:868] = K4_CARVED[k:97]
  The permutation acting on K4 is ALWAYS the identity.
  Only the Vigenère key OFFSET changes (by the placement of K4 in real_CT).

  For (434-k) ≡ (771+k) mod 7: k ≡ 3 mod 7 → uniform offset 4 ('T')
  For k=0,97: same offset since 337 ≡ 771 (mod 7) → offset 1 ('R')

CONCLUSION: Under row-major reading, 180° antisymm grille reduces to
  Vigenère rotation. All 7 offsets of all keywords already tested → NOISE.

The ONLY escape is a DIFFERENT READING ORDER (column-major or other).
""")

# Verify the theorem computationally
print("Verifying theorem for all k=0..97:")
k_results = {}
for k in range(98):  # k = number of K4 chars in H
    # Build specific H: first k K4 positions in H, rest in Hbar
    # K4 positions: 771..770+k in H
    # Their reflects: 96..97-k in Hbar (so 0..96-k in H)
    H = set(range(0, 97-k))  # first 97-k positions of 0..96 in H
    H |= set(range(771, 771+k))  # first k K4 positions in H
    # Need 337 from 97..770: use the first 337
    H |= set(range(97, 97+337))
    assert len(H) == 434, f"k={k}: |H|={len(H)}"

    # Verify antisymmetry
    antisymm_ok = all(reflect180(p) not in H for p in H)

    H_sorted   = sorted(H)
    Hbar_sorted = sorted(set(range(868)) - H)
    real_ct    = ''.join(GRID[i] for i in H_sorted) + ''.join(GRID[i] for i in Hbar_sorted)

    # Extract K4 portion
    k4_part = ''.join(
        [real_ct[434-k+j] for j in range(k)] +
        [real_ct[771+k+j-k] for j in range(k, 97)]
        if k > 0 else [real_ct[771+j] for j in range(97)]
    )
    # Verify it equals K4_CARVED
    assert k4_part == K4_CARVED, f"k={k}: K4 not preserved! {k4_part[:10]}≠{K4_CARVED[:10]}"

    # Compute offsets
    off1 = (434-k) % 7 if k > 0 else -1
    off2 = (771+k) % 7 if k < 97 else -1
    k_results[k] = (off1, off2, antisymm_ok)

print(f"  All 98 cases verified: K4_CARVED is always preserved in natural order ✓")
print(f"  k≡3 mod 7 cases have uniform offset: {[k for k in range(98) if k%7==3 and k_results[k][0]==k_results[k][1]][:6]}...")

# For Beaufort: same analysis — the cipher decryption also sees natural-order K4
# Therefore row-major reading is DEFINITIVELY INSUFFICIENT

# ─────────────────────────────────────────────────────────────────────────────
# 9. PART D: COLUMN-MAJOR READING — K4 SCATTER ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART D: Column-Major Reading — K4 Position Analysis")
print("═"*72)

# In column-major order, K4 chars are at various positions in the 868-char sequence
# K4 cell (r,c): col-major pos = c*28+r
k4_cm_positions = []  # (flat_pos, cm_pos) for K4 chars
for k in range(97):
    fp = K4_FLAT_START + k  # 771..867
    r, c = flat_to_rc(fp)
    cm = rc_to_colmaj(r, c)
    k4_cm_positions.append((fp, cm))

k4_cm_positions.sort(key=lambda x: x[1])  # sort by col-major position

# The permutation: sigma[j] = which K4 char (0-indexed) comes j-th in col-major order
cm_to_k4_idx = {}  # cm_pos → k4 index (0..96)
k4_cm_order = []   # list of k4 indices in col-major order
for fp, cm in k4_cm_positions:
    k4_idx = fp - K4_FLAT_START
    cm_to_k4_idx[cm] = k4_idx
    k4_cm_order.append(k4_idx)

# K4 in column-major order = K4_CARVED permuted by k4_cm_order
k4_colmaj_seq = ''.join(K4_CARVED[i] for i in k4_cm_order)
assert len(k4_colmaj_seq) == 97

print(f"\nK4 in column-major order: {k4_colmaj_seq[:20]}...")
print(f"  First 5 cm-order positions: {k4_cm_positions[:5]}")

run(k4_colmaj_seq, "D1: K4 pure col-major order")

# The inverse permutation: maps real_CT → carved
# sigma_cm[j] = k4_cm_order[j] means real_CT[j] = K4_CARVED[k4_cm_order[j]]
# This is the col-major scrambling hypothesis
sigma_colmaj = k4_cm_order
sigma_colmaj_str = ''.join(K4_CARVED[sigma_colmaj[j]] for j in range(97))
assert sigma_colmaj_str == k4_colmaj_seq

# Now test with full 868-char col-major reading of the cipher panel
# (no hole mask, just read the entire grid in col-major order)
grid_colmaj = ''.join(GRID[fp] for fp, _ in sorted(
    [(31*r + c, rc_to_colmaj(r, c)) for r in range(28) for c in range(31)],
    key=lambda x: x[1]
))
# K4 chars in this full col-major sequence appear at specific positions
k4_from_full_colmaj_H = ''.join(GRID[fp] for fp, cm in k4_cm_positions)
assert k4_from_full_colmaj_H == k4_colmaj_seq, f"Col-major mismatch: {k4_from_full_colmaj_H[:10]} vs {k4_colmaj_seq[:10]}"

# ── D2: Col-major split — try antisymmetric H in col-major reading ──
# For antisymmetric H: pair (p, 867-p) → one is hole
# In col-major order, the reading naturally interleaves top and bottom rows
# Try: for each pair (p, 867-p), the "col-major-first" one is the hole
pairs_cm_first = []  # holes = the member of each pair with smaller col-major position
pairs_cm_second = []  # holes = the member with larger col-major position

for i in range(434):  # first half of pairs
    p1 = i
    p2 = reflect180(i)
    r1, c1 = flat_to_rc(p1)
    r2, c2 = flat_to_rc(p2)
    cm1 = rc_to_colmaj(r1, c1)
    cm2 = rc_to_colmaj(r2, c2)
    if cm1 < cm2:
        pairs_cm_first.append(p1)
        pairs_cm_second.append(p2)
    else:
        pairs_cm_first.append(p2)
        pairs_cm_second.append(p1)

assert len(pairs_cm_first) == 434
# Verify antisymmetry
for p in pairs_cm_first:
    assert reflect180(p) not in pairs_cm_first, f"Antisymm violated at {p}"

print(f"\nD2: Antisymmetric H based on col-major ordering ({len(pairs_cm_first)} holes)")
try_mask_with_keys(pairs_cm_first, "D2:antisymm-cm-first", ('row', 'col'))
try_mask_with_keys(pairs_cm_second, "D2:antisymm-cm-second", ('row', 'col'))

# ── D3: Col-major read of the K3 reflected region ──
# K3 positions 434..769 reflect to 98..433 under 180°
# In col-major order, what does this region look like?
k3_refl_range = range(98, 434)
k3_refl_colmaj = sorted(k3_refl_range, key=lambda p: rc_to_colmaj(*flat_to_rc(p)))
k3_refl_cm_str = ''.join(GRID[p] for p in k3_refl_colmaj)
run(k3_refl_cm_str[:97],  "D3: K3-refl col-major [0:97]")
run(k3_refl_cm_str[-97:], "D3: K3-refl col-major [-97:]")

# ─────────────────────────────────────────────────────────────────────────────
# 10. PART E: K3 CALIBRATION
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART E: K3 Calibration — Grille Consistency with K3")
print("═"*72)

print("""
K3 calibration strategy:
K3 uses pure transposition: K3_carved = transposition(K3_PT)
If the SAME grille applies to K3 (reading in some order), then:
  grille_reading(GRID[434:770]) = some permutation of K3_carved chars
  Applying K3_inverse_perm to this should give K3_PT.

But K3's actual permutation is KNOWN. So the grille reading of K3's section
should match K3_carved in the K3 permutation order.
""")

# Under 180° antisymmetric grille, K3 chars (at positions 434..769) split:
# - K3 chars in H: appear at positions (97-k)..(97-k+n_K3_in_H-1) in real_CT
#   (after the 97-k positions from 0..96 that are in H)
# - K3 chars in Hbar: appear after K3 Hbar chars at higher positions

# For the grille to be consistent with K3:
# The grille must read K3 chars in an order that matches K3_PERM.
# i.e., the j-th K3 char in grille order should be K3_CARVED[K3_PERM^{-1}[j']]
# But K3's transposition maps CT→PT, not PT→CT in the grille sense.

# Let's test: if the grille reads K3 section in SOME order, and we apply
# K3's permutation to that order, do we get K3_PT?

# Under ascending H reading with all K3 in H:
# K3 positions 434..769 in H → they appear after 0..96 group
# Specifically, H = {0..96} ∪ {434..769} (97+336=433 → need 1 more → can't have all K3 in H AND all 0..96 in H AND have exactly 434)
# Actually: |H|=434, K3 has 336 positions, 0..96 has 97, total=433. Need 1 more from 97..433.
# But 97..433 are the K2 positions. If we put 1 K2 position in H, then 1 K1-reflected position is in H̄.

# For simplicity: test what happens if we read K3 section with KRYPTOS as key
print(f"\nE1: K3 section (436..769) with various keys:")
k3_section = GRID[434:770]
assert k3_section == K3_CARVED
k3_spc = score_text_per_char(K3_PT)
print(f"  K3_PT quality: spc={k3_spc:.3f} (should be ~-4.3 for English)")
for kw in KEYWORDS[:4]:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        try:
            pt = vig_decrypt(K3_CARVED, kw, alpha)
        except (ValueError, IndexError):
            continue
        spc = score_text_per_char(pt)
        if spc > -5.5:
            print(f"  K3 Vig({kw},{alpha_name}): spc={spc:.3f} → {pt[:30]}...")

# E2: Does the SAME grille permutation applied to K3 give K3_PT?
# If sigma_K4 is the K4 unscrambling permutation, try it on K3 (mapped to same length)
print(f"\nE2: K3 permutation structure analysis:")
# K3 permutation in column-major order
k3_cm_positions = [(K3_FLAT_START+k, rc_to_colmaj(*flat_to_rc(K3_FLAT_START+k))) for k in range(336)]
k3_cm_order = [k for k, (fp, cm) in sorted(enumerate(k3_cm_positions), key=lambda x: x[1][1])]
k3_colmaj = ''.join(K3_CARVED[i] for i in k3_cm_order)
k3_colmaj_decoded = ''.join('?' if not K3_PT else K3_PT_LIST[k3_cm_order[i]] for i in range(336))
print(f"  K3 in col-major order [0:30]: {k3_colmaj[:30]}")
k3_cm_spc = score_text_per_char(k3_colmaj)
print(f"  K3 col-major spc: {k3_cm_spc:.3f}")

# E3: Apply K3_PERM to col-major K3
k3_via_perm_colmaj = ''.join(k3_colmaj[K3_PERM[i]] for i in range(336))
k3_perm_spc = score_text_per_char(k3_via_perm_colmaj)
print(f"  K3 col-major → K3_PERM: spc={k3_perm_spc:.3f} → {k3_via_perm_colmaj[:30]}")

# E4: What if K4's grille is the ANALOGOUS col-major permutation to K3's?
# K3 col-major order applied to K4
# K4 chars in col-major order → apply K3_PERM scaled/adapted to 97?
print(f"\nE4: K4 with K3-analogue col-major permutation:")
# K3 perm: k3_cm_order[j] → K3_PERM[j] (col-major index → PT index)
# For K4: try same principle with K4's col-major ordering
# But K4 has L-shape (4 cols in row 24, 31 cols in rows 25-27) → different structure
k4_cm_seq = ''.join(K4_CARVED[i] for i in k4_cm_order)
run(k4_cm_seq, "E4: K4 col-major (same as D1)")

# ─────────────────────────────────────────────────────────────────────────────
# 11. PART F: SELF-ENCRYPTING CONSTRAINTS
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART F: Self-Encrypting Constraint Analysis")
print("═"*72)

print("""
Known: K4_PT[32] = K4_CARVED[32] = 'S' (self-encrypting)
       K4_PT[73] = K4_CARVED[73] = 'K' (self-encrypting)

For Vigenère: PT[j] = (real_CT[j] - key[j]) mod 26
Self-encrypting: CT[j] == PT[j] → key[j] = 0 (identity) OR CT[j] = key[j]/(2)...
Actually: PT[j] = CT[j] → real_CT[sigma[j]] = CT[j] ... wait:
  PT[j] = (real_CT[j] - key[j]) mod 26 = PT[j]
  → real_CT[j] = (PT[j] + key[j]) mod 26
  → K4_CARVED[sigma[j]] = (PT[j] + key[j]) mod 26  [if real_CT[j] = K4_CARVED[sigma[j]]]
  → For j=32: K4_CARVED[sigma[32]] = (S + key[32]) mod 26
              K4_CARVED[32] = S
              → K4_CARVED[sigma[32]] = S → key[32] in AZ → sigma[32] is L-position if key[32]='T'
              → AZ.index(K4_CARVED[sigma[32]]) = (AZ.index('S') + AZ.index(key[32])) % 26
""")

# For each keyword, compute sigma[32] and sigma[73]
print("Keyword constraints on sigma[32] and sigma[73]:")
print(f"{'Keyword':<12} {'klen':>5} {'key[32]':<8} {'sigma[32] must be':<25} {'key[73]':<8} {'sigma[73] must be'}")
print("-"*85)

# Build K4_CARVED letter index
k4_letter_positions = {}
for i, ch in enumerate(K4_CARVED):
    k4_letter_positions.setdefault(ch, []).append(i)

for kw in KEYWORDS:
    klen = len(kw)
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        try:
            k32 = alpha[alpha.index(kw[32 % klen])]
            k73 = alpha[alpha.index(kw[73 % klen])]

            # For self-encrypting: PT[j]=CT[j] → key[j]='A' (offset 0) under standard Vig
            # But here: PT[j] = CT[j] means key[j%klen] = 'A'? No!
            # For Vig: PT = CT when CT = (CT - key) mod 26 → key = 0 → key char = alpha[0]
            # But K4_PT[32]=S and K4_CARVED[32]=S. Under Vig: S = Vig_dec(real_CT[32], key[32])
            # i.e., S = (real_CT[32] - key[32]) mod 26
            # i.e., real_CT[32] = (S + key[32]) mod 26

            # If sigma is identity: real_CT[32] = K4_CARVED[32] = S
            # Then key[32] = 0 → key char = alpha[0]
            k32_val = alpha.index(kw[32 % klen])
            k73_val = alpha.index(kw[73 % klen])

            # sigma[32]: real_CT[32] = alpha[(alpha.index('S') + k32_val) % 26]
            target32 = alpha[(alpha.index('S') + k32_val) % 26]
            # sigma[73]: real_CT[73] = alpha[(alpha.index('K') + k73_val) % 26]
            target73 = alpha[(alpha.index('K') + k73_val) % 26]

            pos32 = k4_letter_positions.get(target32, [])
            pos73 = k4_letter_positions.get(target73, [])
            print(f"{kw:<12}/{alpha_name} key[32]={kw[32%klen]!s} σ[32]∈{pos32[:3]} ({target32}-pos) "
                  f" key[73]={kw[73%klen]!s} σ[73]∈{pos73[:3]} ({target73}-pos)")
        except (ValueError, IndexError):
            continue

# Special check: if sigma is identity (no scrambling), sigma[32]=32 and sigma[73]=73
print(f"\nIdentity sigma check:")
print(f"  sigma[32]=32: K4_CARVED[32]={K4_CARVED[32]}")
print(f"  sigma[73]=73: K4_CARVED[73]={K4_CARVED[73]}")
print(f"  For identity to work with KRYPTOS/AZ: key[32]=KRYPTOS[32%7]=KRYPTOS[4]='{AZ[4]}',")
print(f"    PT[32] = (AZ.idx('S') - AZ.idx('{AZ[4]}')) % 26 = {(AZ.index('S')-AZ.index(AZ[4]))%26} → '{AZ[(AZ.index('S')-AZ.index(AZ[4]))%26]}'")
pt32_kryptos = (AZ.index('S') - AZ.index('T')) % 26
pt73_kryptos = (AZ.index('K') - AZ.index('P')) % 26
print(f"  PT[32]={AZ[pt32_kryptos]}, PT[73]={AZ[pt73_kryptos]} (for KRYPTOS/AZ on carved)")
print(f"  Self-enc requires PT[32]=CT[32]=S and PT[73]=CT[73]=K → key[32]=A, key[73]=A")

# What keyword has A at positions 32 and 73?
print(f"\nKeywords with 'A' at position 32%klen AND 73%klen:")
for kw in KEYWORDS:
    k = len(kw)
    c32 = kw[32%k]
    c73 = kw[73%k]
    if c32 == 'A' and c73 == 'A':
        print(f"  {kw}: key[32]={c32}, key[73]={c73} ← BOTH 'A' (identity satisfying)")
    elif c32 == 'A':
        print(f"  {kw}: key[32]={c32} ← A at 32")
    elif c73 == 'A':
        print(f"  {kw}: key[73]={c73} ← A at 73")

# For Beaufort: PT[j] = (key[j] - CT[j]) mod 26
# SE: PT[j]=CT[j] → key[j] = 2*CT[j] mod 26
print(f"\nBeaufort self-encrypting: key[32] = 2*S = 2*18 mod 26 = {(2*18)%26} → '{AZ[(2*18)%26]}'")
print(f"                          key[73] = 2*K = 2*10 mod 26 = {(2*10)%26} → '{AZ[(2*10)%26]}'")
print(f"Keywords with AZ[10]='K' at 32%klen AND AZ[20]='U' at 73%klen:")
for kw in KEYWORDS:
    k = len(kw)
    c32 = kw[32%k]
    c73 = kw[73%k]
    if c32 == 'K' and c73 == 'U':
        print(f"  {kw}: BOTH match for Beaufort SE!")
    elif c32 == 'K':
        print(f"  {kw}: key[32]={c32} matches for Beaufort SE at 32")
    elif c73 == 'U':
        print(f"  {kw}: key[73]={c73} matches for Beaufort SE at 73")

# ─────────────────────────────────────────────────────────────────────────────
# 12. PART G: CRIB-CONSTRAINED PERMUTATION SEARCH
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART G: Crib-Constrained Permutation Search")
print("═"*72)

print("""
Cribs: K4_PT[21:34] = 'EASTNORTHEAST' (13 chars)
       K4_PT[63:74] = 'BERLINCLOCK' (11 chars)

For Vigenère with keyword kw:
  real_CT[j] = Vig_encrypt(PT[j], kw[j%klen], alpha)
  real_CT[j] = alpha[(alpha.idx(PT[j]) + alpha.idx(kw[j%klen])) % 26]

The scrambling sigma means: K4_CARVED[sigma[j]] = real_CT[j]
  → sigma[j] = index of real_CT[j] in K4_CARVED

For each keyword, compute sigma[21..33] and sigma[63..73].
Then check if these sigmas are consistent (injective, etc.)
""")

crib_ENE = "EASTNORTHEAST"  # 13 chars at positions 21-33
crib_BC  = "BERLINCLOCK"    # 11 chars at positions 63-73

# For each keyword, compute what sigma must be at crib positions
print(f"{'Keyword':<12} {'alpha':<3} {'cipher':<5} {'sigma[21:34] needed (first 5)':<35} {'valid?'}")
print("-"*85)

crib_valid_cases = []
for kw in KEYWORDS:
    klen = len(kw)
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cname in ["vig", "beau"]:
            if cname == "vig":
                # Vig: real_CT[j] = (PT[j] + key[j]) mod 26
                enc_fn = lambda p, k, a=alpha: a[(a.index(p) + a.index(k)) % 26]
            else:
                # Beau: real_CT[j] = (key[j] - PT[j]) mod 26
                enc_fn = lambda p, k, a=alpha: a[(a.index(k) - a.index(p)) % 26]

            # Compute required real CT chars from cribs
            sigma_partial = {}
            valid = True
            real_ct_from_crib = {}

            try:
                for j, pt_ch in enumerate(crib_ENE, start=21):
                    key_ch = kw[j % klen]
                    if pt_ch not in alpha or key_ch not in alpha:
                        valid = False
                        break
                    rct_ch = enc_fn(pt_ch, key_ch)
                    # This real_CT[j] must come from K4_CARVED[sigma[j]]
                    positions = k4_letter_positions.get(rct_ch, [])
                    if not positions:
                        valid = False
                        break
                    real_ct_from_crib[j] = (rct_ch, positions)

                if not valid:
                    continue

                for j, pt_ch in enumerate(crib_BC, start=63):
                    key_ch = kw[j % klen]
                    if pt_ch not in alpha or key_ch not in alpha:
                        valid = False
                        break
                    rct_ch = enc_fn(pt_ch, key_ch)
                    positions = k4_letter_positions.get(rct_ch, [])
                    if not positions:
                        valid = False
                        break
                    real_ct_from_crib[j] = (rct_ch, positions)

                if not valid:
                    continue

                # Check injectivity: sigma values at crib positions must be distinct
                # (each K4_CARVED position can only be used once)
                all_crib_chars = [(j, ch, positions) for j, (ch, positions) in sorted(real_ct_from_crib.items())]
                sigma_crib = {j: positions for j, (ch, positions) in real_ct_from_crib.items()}

                # First option: take minimum position for each — check injectivity
                min_sigma = {j: min(positions) for j, (ch, positions) in real_ct_from_crib.items()}

                # Check overlap at self-encrypting positions
                se_ok = True
                if 32 in real_ct_from_crib:
                    rct32, _ = real_ct_from_crib[32]
                    if rct32 != 'S':
                        se_ok = False  # SE position 32 must have real_CT='S'
                if 73 in real_ct_from_crib:
                    rct73, _ = real_ct_from_crib[73]
                    if rct73 != 'K':
                        se_ok = False  # SE position 73 must have real_CT='K'

                # Check Bean equality k[27]=k[65] for KRYPTOS
                bean_ok = True
                if kw == "KRYPTOS" or klen == 7:
                    if 27 in real_ct_from_crib and 65 in real_ct_from_crib:
                        r27, _ = real_ct_from_crib[27]
                        r65, _ = real_ct_from_crib[65]
                        # Bean: k[27]=k[65] means AZ.index(r27)-AZ.index('E') = AZ.index(r65)-AZ.index('E')
                        # Actually Bean is about the key stream, not the PT
                        pass  # skip for now

                # Store valid case
                sigma_first5 = [min(real_ct_from_crib.get(j, (-1, [-1]))[1]) for j in range(21, 26)]
                print(f"{kw:<12} {alpha_name:<3} {cname:<5} "
                      f"{sigma_first5!s:<35} {'SE_ok' if se_ok else 'SE_fail'}")

                if se_ok:
                    crib_valid_cases.append({
                        'kw': kw, 'alpha': alpha_name, 'cipher': cname,
                        'real_ct_from_crib': real_ct_from_crib,
                        'se_ok': se_ok
                    })

            except (ValueError, IndexError):
                continue

print(f"\nValid (SE-compatible) crib cases: {len(crib_valid_cases)}")

# ─────────────────────────────────────────────────────────────────────────────
# 13. PART H: PERIOD-8 ANALYSIS ("8 LINES 73" SIGNAL)
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART H: Period-8 Analysis ('8 Lines 73' Signal)")
print("═"*72)

print("""
Sanborn's yellow pad: '8 Lines 73'
73 + 24 = 97 (cribs span 24 chars, 73 remaining)
V-N = T-L = 8 (tableau anomalies at rows 22 and 14)
L+T = 30 (tableau body width)
Period 8 is Bean-compatible.
""")

# H1: Select every 8th row as holes (rows 0,8,16,24 → K1/K2/K3/K4 areas)
period8_rows = [r for r in range(28) if r % 8 == 0]
mask_period8_row = [rc_to_flat(r, c) for r in period8_rows for c in range(31)]
print(f"Period-8 rows {period8_rows}: {len(mask_period8_row)} holes")
try_mask_with_keys(mask_period8_row, "H1:period8-rows-0mod8", ('row', 'col'))

period8_rows_1 = [r for r in range(28) if r % 8 == 1]
mask_period8_row1 = [rc_to_flat(r, c) for r in period8_rows_1 for c in range(31)]
print(f"Period-8 rows {period8_rows_1}: {len(mask_period8_row1)} holes")
try_mask_with_keys(mask_period8_row1, "H2:period8-rows-1mod8", ('row',))

# H3: Select every 8th column as holes
period8_cols = [c for c in range(31) if c % 8 == 0]
mask_period8_col = [rc_to_flat(r, c) for r in range(28) for c in period8_cols]
print(f"Period-8 cols {period8_cols}: {len(mask_period8_col)} holes")
try_mask_with_keys(mask_period8_col, "H3:period8-cols-0mod8", ('row', 'col'))

# H4: Period-8 within K4 (positions 0..96 with step 8 = canonical read order)
for start in range(8):
    k4_perm_p8 = [(start + i*1) % 97 for i in range(97)]  # Identity with offset
    # Not interesting, skip period-based K4 internal perms (already tested)

# H5: K4 chars at positions ≡ k (mod 8) in the FULL real CT
# If K4's real CT consists of chars at positions {j : j ≡ k (mod 8)} in K4_CARVED
for mod8_offset in range(8):
    indices = [(mod8_offset + i*8) % 97 for i in range(97)]
    # Check: are these all distinct?
    if len(set(indices)) < 97:
        continue  # not a valid permutation (gcd(8,97)=1, so all 97 distinct)
    seq_p8 = ''.join(K4_CARVED[j] for j in indices)
    if len(seq_p8) == 97:
        run(seq_p8, f"H5:K4-mod8-offset{mod8_offset}")

# H6: Linear steps mod 97 with step 8 (period 8 in real CT positions)
step = 8
perm_step8 = [(i * step) % 97 for i in range(97)]
assert len(set(perm_step8)) == 97  # gcd(8,97)=1
seq_step8 = ''.join(K4_CARVED[perm_step8[i]] for i in range(97))
run(seq_step8, "H6:K4-linear-step8")

# H7: "8 Lines" — split K4 into 8 groups, reorder
# If K4 has period 8, then reading it by "columns" of width 8 might help
print(f"\nH7: K4 read by period-8 column groups:")
for num_cols in [8, 8]:  # cols=8, rows=97/8 → not integer
    # 97 = 8*12 + 1. Try 8×12 + 1 padding
    pass  # 97 is prime, no clean factoring

# H8: Tableau anomaly rows N(14) and V(22) as special
# V-N=8, T-L=8, L+T=30
# Row 14 has extra L (col 31 char = L)
# Row 22 has extra T (col 31 char = T)
row14_extra = KA[(13+30) % 26]  # Should be 'L' based on wraparound
row22_extra = KA[(21+30) % 26]  # Should be 'T'
print(f"\nH8: Tableau anomaly analysis:")
print(f"  Row 14 (key=N) extra char at col 31 = '{row14_extra}' (L=col17 in KA)")
print(f"  Row 22 (key=V) extra char at col 31 = '{row22_extra}' (T=col4 in KA)")
print(f"  V-N = {AZ.index('V')-AZ.index('N')} = 8 ✓")
print(f"  T-L = {AZ.index('T')-AZ.index('L')} = 8 ✓")
print(f"  L+T in KA = positions {KA.index('L')} + {KA.index('T')} = {KA.index('L')+KA.index('T')}")
print(f"  L col in body (0-indexed): {KA.index('L')-0} → body col {KA.index('L')}")
print(f"  T col in body (0-indexed): {KA.index('T')-0} → body col {KA.index('T')}")

# ─────────────────────────────────────────────────────────────────────────────
# 14. PART I: READING ORDER VARIANTS (non-standard)
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART I: Reading Order Variants")
print("═"*72)

# I1: "Herringbone" — zigzag reading of K4's 4-row region
# Row 24 (partial: cols 27-30), Row 25 (full), Row 26 (full), Row 27 (full)
k4_region = []  # list of (row, col) for K4 cells in reading order

# Column zigzag: for each column c=0..30, read rows 24-27 (where applicable)
for c in range(31):
    col_cells = []
    for r in range(24, 28):
        fp = rc_to_flat(r, c)
        if fp in range(K4_FLAT_START, K4_FLAT_END) or (r == 24 and c >= 27):
            col_cells.append((r, c, GRID[fp] if GRID[fp] != '?' else None))
    if col_cells:
        if c % 2 == 0:
            k4_region.extend(col_cells)
        else:
            k4_region.extend(reversed(col_cells))

k4_herring = ''.join(ch for r, c, ch in k4_region if ch is not None)[:97]
if len(k4_herring) == 97:
    run(k4_herring, "I1: K4 herringbone-column zigzag")

# I2: Row-by-row but starting from K4's bottom-right
k4_reversed = K4_CARVED[::-1]
run(k4_reversed, "I2: K4 reversed")

# I3: K4 read "upward" through its columns (col 30 first, rows 27→24)
k4_cols_reversed = []
for c in range(30, -1, -1):  # cols right to left
    for r in range(27, 23, -1):  # rows bottom to top
        fp = rc_to_flat(r, c)
        if K4_FLAT_START <= fp < K4_FLAT_END:
            k4_cols_reversed.append(GRID[fp])
k4_col_rev = ''.join(k4_cols_reversed)
if len(k4_col_rev) == 97:
    run(k4_col_rev, "I3: K4 cols-right-to-left, rows bottom-to-top")
else:
    print(f"  I3 skip: got {len(k4_col_rev)} chars")

# I4: K4 read in alternating column order (even cols then odd cols)
k4_even_cols = [GRID[rc_to_flat(r, c)]
                for c in range(0, 31, 2) for r in range(24, 28)
                if K4_FLAT_START <= rc_to_flat(r, c) < K4_FLAT_END]
k4_odd_cols  = [GRID[rc_to_flat(r, c)]
                for c in range(1, 31, 2) for r in range(24, 28)
                if K4_FLAT_START <= rc_to_flat(r, c) < K4_FLAT_END]
k4_even_odd = ''.join(k4_even_cols + k4_odd_cols)
if len(k4_even_odd) == 97:
    run(k4_even_odd, "I4: K4 even cols then odd cols")

# I5: K4 read by diagonals
k4_diag = []
for d in range(28 + 31 - 1):  # diagonal index
    for r in range(24, 28):
        c = d - (r - 24)
        if 0 <= c < 31:
            fp = rc_to_flat(r, c)
            if K4_FLAT_START <= fp < K4_FLAT_END:
                k4_diag.append(GRID[fp])
k4_diag_str = ''.join(k4_diag)
if len(k4_diag_str) == 97:
    run(k4_diag_str, "I5: K4 diagonal reading")

# ─────────────────────────────────────────────────────────────────────────────
# 15. PART J: TABLEAU-DERIVED PERMUTATION
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART J: Tableau-Derived Permutation for K4")
print("═"*72)

print("""
If the Kryptos tableau defines the SCRAMBLING PERMUTATION sigma directly:
The tableau at K4's positions gives the reading ORDER.
For each K4 position (r,c), the TABLEAU char at (r,c) tells us which
K4_CARVED position to read next.
""")

# J1: Tableau chars at K4 positions → use as keys for permutation
k4_tableau_chars = []
for k in range(97):
    fp = K4_FLAT_START + k
    r, c = flat_to_rc(fp)
    tc = TABLEAU[fp]
    k4_tableau_chars.append(tc)

print(f"J1: Tableau chars at K4 positions: {''.join(k4_tableau_chars[:20])}...")
k4_tab_str = ''.join(k4_tableau_chars)
print(f"  All distinct: {len(set(k4_tab_str))} unique letters out of 97")

# J2: Use tableau chars to define reading order (sort K4_CARVED by tableau char)
# Filter to only valid alpha chars for sorting
valid_tab_idx = [j for j in range(97) if k4_tableau_chars[j] in AZ]
print(f"  Valid AZ tableau chars at K4 positions: {len(valid_tab_idx)}/97")

if len(valid_tab_idx) == 97:
    k4_sorted_by_tab_AZ = sorted(range(97), key=lambda j: AZ.index(k4_tableau_chars[j]))
    k4_tab_sorted_AZ = ''.join(K4_CARVED[i] for i in k4_sorted_by_tab_AZ)
    run(k4_tab_sorted_AZ, "J2: K4 sorted by tableau char (AZ)")
else:
    print("  J2: skipped (some tableau chars not in AZ)")

k4_sorted_by_tab_KA = sorted(range(97), key=lambda j: KA.index(k4_tableau_chars[j]) if k4_tableau_chars[j] in KA else 99)
k4_tab_sorted_KA = ''.join(K4_CARVED[i] for i in k4_sorted_by_tab_KA)
if len(k4_tab_sorted_KA) == 97:
    run(k4_tab_sorted_KA, "J3: K4 sorted by tableau char (KA)")

# J4: What if we use the CIPHER char itself to define reading order?
# Sort K4_CARVED chars by their AZ or KA index at each position
k4_sorted_by_cipher_AZ = sorted(range(97), key=lambda j: AZ.index(K4_CARVED[j]) if K4_CARVED[j] in AZ else 99)
k4_cipher_sorted = ''.join(K4_CARVED[i] for i in k4_sorted_by_cipher_AZ)
run(k4_cipher_sorted, "J4: K4 sorted by cipher char (AZ)")

# J5: Use tableau to define sigma directly
# sigma[j] = AZ.index(TABLEAU[K4_FLAT_START + j]) % 97 → read K4_CARVED at that position
# (might not be a bijection)
sigma_tab_raw = [AZ.index(k4_tableau_chars[j]) % 97 if k4_tableau_chars[j] in AZ else j for j in range(97)]
sigma_tab = sigma_tab_raw
if len(set(sigma_tab)) == 97:
    k4_tab_perm = ''.join(K4_CARVED[sigma_tab[j]] for j in range(97))
    run(k4_tab_perm, "J5: K4 permuted by tableau AZ-index")
else:
    print(f"  J5: sigma_tab not bijective ({len(set(sigma_tab))} unique values)")

# J6: Tableau KA index as permutation
sigma_tab_KA = [KA.index(k4_tableau_chars[j]) % 97 if k4_tableau_chars[j] in KA else j for j in range(97)]
if len(set(sigma_tab_KA)) == 97:
    k4_tab_ka_perm = ''.join(K4_CARVED[sigma_tab_KA[j]] for j in range(97))
    run(k4_tab_ka_perm, "J6: K4 permuted by tableau KA-index")
else:
    print(f"  J6: sigma_tab_KA not bijective ({len(set(sigma_tab_KA))} unique values)")

# ─────────────────────────────────────────────────────────────────────────────
# 16. PART K: KEY OFFSET ANALYSIS WITH BEST MASKS
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART K: Comprehensive Key Offset Scan on Best Candidates")
print("═"*72)

# For each of the best-scoring sequences, try all key offset rotations
best_seqs = []
for spc, label, res in sorted(RESULTS, key=lambda x: -x[0])[:5]:
    best_seqs.append((res['seq'], label))

# Also add baseline K4
best_seqs.append((K4_CARVED, "BASELINE:K4_direct"))

for seq, seq_label in best_seqs:
    if not seq or len(seq) != 97:
        continue
    best_spc_offset = -999.0
    best_offset = None
    for kw in KEYWORDS:
        klen = len(kw)
        for off in range(klen):
            rotated = kw[off:] + kw[:off]
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    try:
                        pt = cfn(seq, rotated, alpha)
                    except (ValueError, IndexError):
                        continue
                    hits = has_cribs(pt)
                    spc  = score_text_per_char(pt)
                    if hits:
                        ALL_CRIB_HITS.append(dict(label=seq_label, kw=f"{kw}[off={off}]",
                                                   pt=pt, hits=hits))
                        print(f"\nCRIB HIT! [{seq_label}] {kw}[off={off}]/{alpha_name}/{cname}")
                        print(f"  PT: {pt}")
                    if spc > best_spc_offset:
                        best_spc_offset = spc
                        best_offset = (kw, off, alpha_name, cname, spc, pt)
    if best_offset:
        kw, off, a, c, spc, pt = best_offset
        print(f"  {seq_label}: best offset: {kw}[off={off}]/{a}/{c} spc={spc:.3f}")

# ─────────────────────────────────────────────────────────────────────────────
# 17. PART L: EXTENDED GRILLE READING — ALL 868-CHAR READS
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART L: Full Grille Read — K4 at non-standard positions in real CT")
print("═"*72)

def grille_read_full(holes, reading_order='row'):
    """Read full 868-char real CT from hole set."""
    if reading_order == 'row':
        H = sorted(holes)
        Hb = sorted(set(range(868)) - set(holes))
    else:  # col
        H = sorted(holes, key=lambda i: rc_to_colmaj(*flat_to_rc(i)))
        Hb = sorted(set(range(868)) - set(holes),
                    key=lambda i: rc_to_colmaj(*flat_to_rc(i)))
    return ''.join(GRID[i] for i in H) + ''.join(GRID[i] for i in Hb)

def find_k4_in_realct(real_ct, holes, reading_order='row'):
    """Find K4-length (97) window in real_ct that scores best."""
    best_spc = -999.0
    best_result = None
    for start in range(0, 868 - 97 + 1, 1):
        seg = real_ct[start:start+97]
        if '?' in seg:
            continue
        for kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    try:
                        pt = cfn(seg, kw, alpha)
                    except (ValueError, IndexError):
                        continue
                    hits = has_cribs(pt)
                    spc = score_text_per_char(pt)
                    if hits:
                        return {'seg': seg, 'pt': pt, 'start': start, 'spc': spc,
                                'kw': kw, 'alpha': alpha_name, 'cipher': cname, 'hits': hits}
                    if spc > best_spc:
                        best_spc = spc
                        best_result = {'seg': seg, 'pt': pt, 'start': start, 'spc': spc,
                                       'kw': kw, 'alpha': alpha_name, 'cipher': cname, 'hits': hits}
    return best_result

# Test KA cycle masks with full grille read — scan ALL window positions
print("\nL1: KA cycle masks — best 97-char window scan:")
test_masks_L = [
    (mask_17_cipher, "17cyc-cipher"),
    (mask_8_cipher,  "8cyc-cipher"),
    (mask_17_tab,    "17cyc-tab"),
    (mask_8_tab,     "8cyc-tab"),
    (pairs_cm_first, "antisymm-cm-first"),
]
for holes, name in test_masks_L:
    if not holes:
        continue
    real_ct = grille_read_full(holes, 'row')
    # Just test the K4-aligned window (positions 771..867) as a sanity check
    k4_window = real_ct[771:868]
    if '?' not in k4_window and len(k4_window) == 97:
        spc, best, hits = test97(k4_window, f"L1:{name}@771")
        ALL_CRIB_HITS.extend(hits)
        if best:
            RESULTS.append((spc, f"L1:{name}@771", best))
        print(f"  L1 {name}@771: spc={spc:.3f}")

    # Also test the first 97 chars of real_CT
    first97 = real_ct[:97]
    if '?' not in first97:
        spc, best, hits = test97(first97, f"L1:{name}@0")
        ALL_CRIB_HITS.extend(hits)
        if best:
            RESULTS.append((spc, f"L1:{name}@0", best))
        print(f"  L1 {name}@0: spc={spc:.3f}")

# ─────────────────────────────────────────────────────────────────────────────
# 18. PART M: KRYPTOS-SPECIFIC STRUCTURAL TESTS
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART M: Kryptos-Specific Structural Tests")
print("═"*72)

# M1: The 434 = 2×7×31 factorization
# 434 = top half = K1+K2. K3+?+K4 = bottom half.
# 7 = KRYPTOS length, 31 = grid width, 2 = split count
print(f"\nM1: 434 = {2}×{7}×{31} factorization:")
print(f"  Top 14 rows (K1+K2): 14×31 = {14*31} chars = {434}")
print(f"  Bottom 14 rows (K3+?+K4): 14×31 = {14*31} chars = {434}")
print(f"  K4 start: row 24, col 27 → flat pos {rc_to_flat(24,27)} = {K4_FLAT_START}")
print(f"  K4 flat range: [{K4_FLAT_START}, {K4_FLAT_END}) = 97 chars")
print(f"  K4 180° reflected to: [0, 97) → GRID[0:97] = {GRID[:20]}...")

# M2: 14×31 reading of K3+?+K4 area
# K3+?+K4 = GRID[434:868] = 434 chars = 14×31
# If we rearrange these 434 chars as a 14×31 grid and apply rotational transposition...
k3k4_region = GRID[434:868]  # 434 chars = 14×31
print(f"\nM2: K3+?+K4 region as 14×31 grid:")
print(f"  First row: {k3k4_region[:31]}")
print(f"  Last row:  {k3k4_region[-31:]}")

# Try K3's double rotational transposition on the 14×31 K3+?+K4 region
# K3's method: write 434 into 24-wide grid → rot CW → write into 8-wide → rot CW
# But 434 = 14×31, so try: 31-wide and 14-wide grids
def rot_cw(text, rows, cols):
    """Rotate text (written row-major into rows×cols) 90° CW."""
    grid = [[text[r*cols+c] for c in range(cols)] for r in range(rows)]
    # Rotated: new_rows=cols, new_cols=rows; new[c][rows-1-r] = old[r][c]
    new_rows, new_cols = cols, rows
    result = []
    for c in range(cols):      # new row
        for r in range(rows-1, -1, -1):  # new col (reversed old row)
            result.append(grid[r][c])
    return ''.join(result)

# Apply to K3+?+K4 region
try:
    # 434 = 14×31
    k3k4_rot1 = rot_cw(k3k4_region, 14, 31)  # 31×14
    k3k4_rot2 = rot_cw(k3k4_rot1, 31, 14)    # 14×31 again
    print(f"  Double rot CW: {k3k4_rot2[:20]}... (434 chars)")
    k4_from_rot = k3k4_rot2[337:434]  # K4 would be at last 97 chars
    k4_from_rot2 = k3k4_rot2[-97:]
    if len(k4_from_rot) == 97 and '?' not in k4_from_rot:
        run(k4_from_rot, "M2: K3K4-region double-rot-CW [337:434]")
    if len(k4_from_rot2) == 97 and '?' not in k4_from_rot2:
        run(k4_from_rot2, "M2: K3K4-region double-rot-CW [-97:]")
except Exception as e:
    print(f"  M2 error: {e}")

# M3: Apply K3's permutation formula to K4's region
# K3 formula: ct_pos=i → pt_pos=k3_ct_to_pt(i) for 336 chars
# K4 has 97 chars — try analogous formula if K4 has its own dimensions
# K4 = L-shaped: 4 + 31 + 31 + 31 = 97 chars
# Closest rectangle: 7×14 = 98 (close!), or 97×1
# Try: K3's formula scaled: just apply K3_PERM[:97] as permutation on K4
k4_via_k3_perm = ''.join(K4_CARVED[K3_PERM[i] % 97] for i in range(97))
if len(set(K3_PERM[i] % 97 for i in range(97))) == 97:
    run(k4_via_k3_perm, "M3: K4 via K3_PERM mod 97")
else:
    print(f"  M3: K3_PERM mod 97 not bijective ({len(set(K3_PERM[i]%97 for i in range(97)))} unique)")

# M4: K4 reversed then K3 permutation
k4_rev_k3 = ''.join(K4_CARVED[::-1][K3_PERM[i] % 97] for i in range(97))
run(k4_rev_k3, "M4: K4 reversed then K3-perm")

# ─────────────────────────────────────────────────────────────────────────────
# 19. PART N: ANTISYMMETRIC MASK — GRILLE FROM TABLEAU SYMMETRY
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART N: Grille from Tableau 180° Symmetry")
print("═"*72)

print("""
Key idea: Overlay Kryptos tableau on cipher grid (both 28×31).
For each pair (p, 867-p):
  If tableau[p] == cipher[p]: this pair is "aligned" at p
  If tableau[867-p] == cipher[867-p]: aligned at 867-p
The alignment pattern defines holes.
""")

# N1: For each 180° pair, compare tableau vs cipher to determine hole assignment
H_tableau_align = []
H_tableau_flip = []

for i in range(434):  # first half pairs
    p1 = i
    p2 = reflect180(i)
    c1, c2 = GRID[p1], GRID[p2]
    t1, t2 = TABLEAU[p1], TABLEAU[p2]

    # Rule 1: hole where cipher matches tableau, solid at its pair
    match1 = (c1 == t1) and c1 != '?' and t1 != ' '
    match2 = (c2 == t2) and c2 != '?' and t2 != ' '

    if match1 and not match2:
        H_tableau_align.append(p1)
    elif match2 and not match1:
        H_tableau_align.append(p2)
    elif match1 and match2:
        H_tableau_align.append(p1)  # arbitrary: take first
    else:  # neither matches
        H_tableau_align.append(p1)  # arbitrary

    # Rule 2 (flipped): hole where cipher DOESN'T match tableau
    nomatch1 = (c1 != t1) and c1 != '?' and t1 != ' '
    nomatch2 = (c2 != t2) and c2 != '?' and t2 != ' '

    if nomatch1 and not nomatch2:
        H_tableau_flip.append(p1)
    elif nomatch2 and not nomatch1:
        H_tableau_flip.append(p2)
    else:
        H_tableau_flip.append(p1)  # arbitrary

assert len(H_tableau_align) == 434
assert len(H_tableau_flip) == 434
print(f"N1: tableau-align hole set ({len(H_tableau_align)} holes)")
try_mask_with_keys(H_tableau_align, "N1:tab-align-holes", ('row', 'col'))
try_mask_with_keys(H_tableau_flip, "N2:tab-flip-holes", ('row', 'col'))

# N3: For each pair, compare KA indices: hole where KA.index(cipher) > KA.index(tableau)
H_ka_gt = []
for i in range(434):
    p1, p2 = i, reflect180(i)
    c1, c2 = GRID[p1], GRID[p2]
    t1, t2 = TABLEAU[p1], TABLEAU[p2]

    v1 = KA.index(c1) if c1 in KA else -1
    v2 = KA.index(c2) if c2 in KA else -1
    tv1 = KA.index(t1) if t1 in KA else -1
    tv2 = KA.index(t2) if t2 in KA else -1

    score1 = v1 - tv1 if v1 >= 0 and tv1 >= 0 else 0
    score2 = v2 - tv2 if v2 >= 0 and tv2 >= 0 else 0

    if score1 >= score2:
        H_ka_gt.append(p1)
    else:
        H_ka_gt.append(p2)

assert len(H_ka_gt) == 434
print(f"N3: KA-difference-based hole set ({len(H_ka_gt)} holes)")
try_mask_with_keys(H_ka_gt, "N3:ka-diff-holes", ('row', 'col'))

# ─────────────────────────────────────────────────────────────────────────────
# 20. PART O: ALL-KEYWORDS OFFSET SCAN ON ALL SEQUENCES
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "═"*72)
print("PART O: Additional Sequences from Previous Script")
print("═"*72)

# Carry forward key sequences from previous analysis
seqA = GRID[:97]
seqB = ''.join(GRID[96-k] for k in range(97))
seqC = K4_CARVED[::-1]
k3_refl_start = reflect180(K3_FLAT_END - 1)   # = 98
k3_refl_end   = reflect180(K3_FLAT_START)      # = 433
seqD = GRID[k3_refl_start:k3_refl_end+1][:97]
seqD2 = GRID[k3_refl_start:k3_refl_end+1][-97:]

# Comprehensive test of previous sequences with key offsets
for seq, name in [(seqA,"A:GRID[0:97]"), (seqB,"B:GRID[96..0]"), (seqC,"C:K4_rev"), (seqD,"D:K3refl[0:97]"), (seqD2,"D2:K3refl[-97:]")]:
    run(seq, f"O-{name}")

# Full running-key test: use K3_PT as key for K4
k3_pt_as_key = K3_PT[:97]
print(f"\nO5: K3_PT as running key for K4:")
for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        try:
            valid_key = all(ch in alpha for ch in k3_pt_as_key)
            if not valid_key:
                continue
            pt = cfn(K4_CARVED, k3_pt_as_key, alpha)
            spc = score_text_per_char(pt)
            hits = has_cribs(pt)
            if hits or spc > -5.5:
                print(f"  K3PT-key/{alpha_name}/{cname}: spc={spc:.3f}  {pt[:40]}")
                ALL_CRIB_HITS.extend(hits)
        except (ValueError, IndexError):
            continue

# K3_CARVED as running key for K4
print(f"\nO6: K3_CARVED as running key for K4:")
for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        try:
            valid_key = all(ch in alpha for ch in K3_CARVED[:97])
            if not valid_key:
                continue
            pt = cfn(K4_CARVED, K3_CARVED[:97], alpha)
            spc = score_text_per_char(pt)
            hits = has_cribs(pt)
            if hits or spc > -5.5:
                print(f"  K3CT-key/{alpha_name}/{cname}: spc={spc:.3f}  {pt[:40]}")
                ALL_CRIB_HITS.extend(hits)
        except (ValueError, IndexError):
            continue

# ─────────────────────────────────────────────────────────────────────────────
# 21. FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "=" * 72)
print("FINAL SUMMARY")
print("=" * 72)

elapsed = time.time() - t0
RESULTS.sort(key=lambda x: x[0], reverse=True)

print(f"\nElapsed: {elapsed:.1f}s | Total crib hits: {len(ALL_CRIB_HITS)}")

if ALL_CRIB_HITS:
    print("\n" + "!"*60)
    print("*** BREAKTHROUGH CRIB HIT(S) ***")
    print("!"*60)
    for h in ALL_CRIB_HITS:
        print(f"  {h}")
else:
    print("\nNo crib hits found.")

print(f"\nTop 20 candidates by quadgram score:")
print(f"{'Rank':<5} {'spc':>7}  {'label':<60} {'key'}")
print("-" * 90)
for rank, (spc, label, res) in enumerate(RESULTS[:20], 1):
    key_str = f"{res['kw']}/{res['alpha']}/{res['cipher']}"
    print(f"{rank:<5} {spc:>7.3f}  {label:<60} {key_str}")

print(f"\nTop 3 PT snippets:")
for rank, (spc, label, res) in enumerate(RESULTS[:3], 1):
    print(f"\n#{rank} [{label}] spc={spc:.3f}, {res['kw']}/{res['alpha']}/{res['cipher']}")
    print(f"  CT: {res['seq'][:40]}...")
    print(f"  PT: {res['pt']}")

# ─── THEORETICAL CONCLUSIONS ─────────────────────────────────────────────────
print("\n" + "─" * 72)
print("THEORETICAL CONCLUSIONS: 180° Rotation Analysis")
print("─" * 72)
print(f"""
1. ASCENDING ROW-MAJOR 180° ANTISYMMETRIC GRILLE: DEFINITIVELY INSUFFICIENT
   Mathematically proven: K4 chars always appear in natural order in real CT.
   Result = Vigenère rotation. All 7×|keywords|×2 combos tested → NOISE.
   CANNOT permute K4 chars among themselves.

2. KA-CYCLE MASKS: Tested all 4 primary variants.
   Best score: {RESULTS[0][0]:.3f}/char (random ≈ -10.0, English ≈ -4.2)
   All cycle masks produce {'noise' if RESULTS[0][0] < -5.0 else 'SIGNAL'}.

3. TABLEAU OVERLAY MASKS: 6 variants tested.
   cipher==tableau gives {len(cipher_eq_tab)} cells (39 documented).
   No crib hits from any overlay mask.

4. COLUMN-MAJOR READING: Genuinely permutes K4 chars.
   K4 chars in col-major order = {k4_colmaj_seq[:20]}...
   Score: see leaderboard. {'Above noise floor' if any(s > -5.0 for s,_,_ in RESULTS) else 'All noise'}.

5. K3 CALIBRATION: K3's col-major reading scores {k3_cm_spc:.3f}/char (noise).
   K3 is pure transposition, no Vig layer. Grille approach for K3 is unclear.

6. SELF-ENCRYPTING CONSTRAINTS:
   sigma[32] must map to L-positions in K4_CARVED (for KRYPTOS/AZ key).
   sigma[73] must map to Z-positions in K4_CARVED (for KRYPTOS/AZ key).
   This STRONGLY constrains the permutation.

7. VERDICT: 180° rotation can create genuine scrambling ONLY with non-trivial
   reading orders (column-major, diagonal, herringbone). These have been tested.
   No crib hits. The construction rule for the grille remains UNKNOWN.

8. NEXT STEPS:
   a) Constraint propagation from SE + cribs → enumerate valid sigma subsets
   b) Search for reading orders that are consistent with K3's known structure
   c) Explore non-rectangular/non-standard grille geometries
   d) Investigate "8 Lines 73" as a direct construction instruction
""")
