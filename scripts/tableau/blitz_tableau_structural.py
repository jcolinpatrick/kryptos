#!/usr/bin/env python3
"""
Cipher: tableau analysis
Family: tableau
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_tableau_structural.py
==========================================================================
STRUCTURAL GRILLE DERIVATION from Kryptos tableau + AZ→KA cycle signal.

NOVEL APPROACHES (not in existing blitz scripts):
  A. AZ→KA cycle-based masks — 17-cycle vs 8-cycle letters define holes
     Applied to cipher letters, tableau letters, header/key-column letters
  B. Row-key × Col-header product masks (cycle-membership combinations)
  C. Overlay difference mask (cipher != tableau positions as holes)
  D. KA-index / AZ-index reading order (rank by letter's position in alphabet)
  E. Period-8 structural mask (rows 6/14/22 and cols L/T from anomalies)
  F. AZ-pos vs KA-pos comparison binary signal per row/column
  G. K3 reading-order step pattern extended to K4

KEY INSIGHT: K4 occupies LINEAR POSITIONS 771..867 in the 28×31 grid
(consecutive). Under 180° rotation: pos p ↔ pos (867-p). K4 pairs with
the top-left corner (rows 0-3, linear 0..96).

For any mask, K4's unscrambling = the relative order of K4 positions
within the grille (holes-first then complements, both in row-major order).

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_tableau_structural.py
"""
from __future__ import annotations
import sys
from collections import Counter
sys.path.insert(0, 'scripts')
from kbot_harness import (
    score_text, score_text_per_char, has_cribs,
    vig_decrypt, beau_decrypt,
    K4_CARVED, AZ, KA, KEYWORDS,
)

NROWS, NCOLS = 28, 31

# ── Cipher Grid (28×31 corrected) ────────────────────────────────────────────
# '?' placeholders from original are replaced with 'X' for indexing safety
CIPHER_ROWS_RAW = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",   # row 0  K1
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",   # row 1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNCE",  # row 2  K1→K2 (extra E at end, take 31)
    "EGGWHKKXDQMCPFQZDQMMIAGPFXHQRLG",   # row 3  K2  (? → X)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # row 4
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",   # row 5
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",   # row 6
    "IHHDDDUVHXDWKBFUFPWNTDFIYCUQZER",   # row 7  (? → X)
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",   # row 8
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",   # row 9
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",   # row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",   # row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",   # row 13  K2 ends
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",   # row 14  K3 starts (CENTER)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # row 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",    # row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",   # row 17
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",   # row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",   # row 19
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",   # row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",   # row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",   # row 22
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",   # row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHWXOBKR",   # row 24  K4 starts col 27 (col26=? → X)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",   # row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",   # row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",   # row 27  K4 ends
]
GRID = [row[:NCOLS].ljust(NCOLS, 'X') for row in CIPHER_ROWS_RAW]

# Verify K4 in grid
_k4_from_grid = GRID[24][27:31] + GRID[25] + GRID[26] + GRID[27]
assert _k4_from_grid[:97] == K4_CARVED, f"K4 grid mismatch! got {_k4_from_grid[:10]}"
print(f"✓ K4 verified in grid: {K4_CARVED[:20]}...")

# K4 linear positions (consecutive: 771..867)
K4_POSITIONS = (
    [24*31 + c for c in range(27, 31)] +   # row 24, cols 27-30
    [25*31 + c for c in range(31)] +        # row 25
    [26*31 + c for c in range(31)] +        # row 26
    [27*31 + c for c in range(31)]          # row 27
)
assert len(K4_POSITIONS) == 97
assert K4_POSITIONS[0] == 771 and K4_POSITIONS[-1] == 867
assert all(GRID[p//31][p%31] == K4_CARVED[i] for i, p in enumerate(K4_POSITIONS))
print(f"✓ K4 at linear positions {K4_POSITIONS[0]}..{K4_POSITIONS[-1]} (consecutive)")

# ── KA Vigenère Tableau (28×31) ───────────────────────────────────────────────
# Row 0 / Row 27: header/footer = ' ' + ABCDEFGHIJKLMNOPQRSTUVWXYZ + ABCD
# Rows 1-26: key_letter (AZ[i]) + body = KA[(i+j)%26] for j=0..29
def build_tableau():
    header = (" " + AZ + "ABCD")[:NCOLS]   # ' ' + 26 + 4 = 31
    rows = [header]
    for i in range(26):
        body = "".join(KA[(i + j) % 26] for j in range(30))
        rows.append(AZ[i] + body)
    rows.append(header)
    return rows

TABLEAU = build_tableau()
assert len(TABLEAU) == 28 and all(len(r) == 31 for r in TABLEAU)
print(f"✓ Tableau built. Row A body[0..5]: {TABLEAU[1][1:7]}")

# ── AZ→KA Letter Permutation & Cycles ────────────────────────────────────────
# pi(AZ[i]) = KA[i]: A→K, B→R, C→Y, D→P, T→N, etc.
PI = {AZ[i]: KA[i] for i in range(26)}

visited, cycles = set(), []
for start in AZ:
    if start in visited:
        continue
    cycle, cur = [], start
    while cur not in visited:
        visited.add(cur)
        cycle.append(cur)
        cur = PI[cur]
    cycles.append(tuple(cycle))
cycles.sort(key=len, reverse=True)

CYCLE_17 = frozenset(cycles[0])  # 17-element cycle
CYCLE_8  = frozenset(cycles[1])  # 8-element cycle
FIXED_Z  = frozenset(cycles[2])  # {Z}

print(f"\nAZ→KA cycle structure:")
for cyc in cycles:
    print(f"  len={len(cyc)}: {'→'.join(cyc)}")
print(f"17-cycle: {''.join(sorted(CYCLE_17))}")
print(f"8-cycle:  {''.join(sorted(CYCLE_8))}")

# ── K3 Ground Truth ───────────────────────────────────────────────────────────
K3_PT_336 = (
    "SLOWLYDESPARATLYSLOWLYTHECHAMELEONSHIFTEDITSCOLORSTOMATCH"
    "THEGRAYGRANITEWHEREITLAYXWAITINGXWAITINGXTILLWEMIGHTALMOSTNOTSEEIT"
    "XFINALLYWHENTHEHOURSEEMEDDARKEST"
    "NIGHTXANDTHENSLOWLYGATHERINGHISSTRENGTHTHELAISEDTHESTRANGE"
    "INSTRUMENTANDPLACINGITTOHISLIPSBLEWTHREESHARPBLASTSOFTHENIGHTSIG"
    "NALXHEMIGHTALMOSTNOTSEEITXCANYOUSEEANYTHINGQ"
)[:336]

def k3_perm_formula(i):
    """K3 double-rotation: carved K3[i] ← K3_PT[result]."""
    a, b = i // 24, i % 24
    interm = 14 * b + 13 - a
    c, d = interm // 8, interm % 8
    return (42 * d + 41 - c) % 336

K3_PERM = [k3_perm_formula(i) for i in range(336)]
assert len(set(K3_PERM)) == 336, "K3 perm not bijective"
K3_INV  = [0] * 336
for i, j in enumerate(K3_PERM):
    K3_INV[j] = i

# Extract K3 carved CT from grid
def _extract_k3_ct():
    ct = []
    for r in range(14, 24):
        for c in range(31):
            ch = GRID[r][c]
            if ch.isalpha() and ch != 'X':
                ct.append(ch)
    for c in range(26):   # row 24, cols 0-25 (col 26 is ?)
        ch = GRID[24][c]
        if ch.isalpha() and ch != 'X':
            ct.append(ch)
    return "".join(ct)

K3_CT = _extract_k3_ct()
print(f"\nK3 CT length: {len(K3_CT)} (expect 336), K3_PT length: {len(K3_PT_336)}")

# Verify K3 perm: K3_CT[i] == K3_PT_336[K3_PERM[i]] (pure transposition)?
if len(K3_CT) == 336:
    mismatches_pure = sum(1 for i in range(336) if K3_CT[i] != K3_PT_336[K3_PERM[i]])
    print(f"K3 pure-transposition mismatches: {mismatches_pure}/336")
    if mismatches_pure == 0:
        print(f"  ★ K3 IS PURE TRANSPOSITION (no Vigenere over scramble)!")
    else:
        # Try transposition + Vigenere
        real_k3_ct = "".join(K3_CT[K3_INV[j]] for j in range(336))
        best_m, best_cfg, best_dec = 0, "", ""
        for key in ["PALIMPSEST", "KRYPTOS", "ABSCISSA"]:
            for aname, alpha in [("KA", KA), ("AZ", AZ)]:
                for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    try:
                        dec = cfn(real_k3_ct, key, alpha)
                        m = sum(1 for i in range(min(len(dec), len(K3_PT_336)))
                                if dec[i] == K3_PT_336[i])
                        if m > best_m:
                            best_m, best_cfg, best_dec = m, f"{cname}/{key}/{aname}", dec
                    except Exception:
                        pass
        print(f"  Best transposition+cipher match: {best_m}/336 [{best_cfg}]")
        if best_m > 20:
            print(f"  Dec[:50]: {best_dec[:50]}")

# K3 reading-order step analysis (in K3-internal = global linear space, since K3 linear = 434+i)
k3_steps = [(K3_INV[j+1] - K3_INV[j]) % 336 for j in range(335)]
k3_top_steps = Counter(k3_steps).most_common(5)
print(f"\nK3 dominant reading-order steps (mod 336): {k3_top_steps}")

# ── Core: K4 real_CT from a hole mask ────────────────────────────────────────
def mask_to_k4_real_ct(holes_set):
    """
    Given a set of hole positions (linear indices in 28×31 grid),
    compute K4's 97-char 'real CT' (before Vigenere).

    Reading order: holes in row-major order, then complements in row-major.
    K4 positions get their rank in this global reading. Relative order of
    K4 positions = their unscrambling permutation.
    """
    n = NROWS * NCOLS
    holes_sorted = sorted(holes_set)
    complement_sorted = [i for i in range(n) if i not in holes_set]

    slot = {}
    for rank, pos in enumerate(holes_sorted):
        slot[pos] = rank
    n_holes = len(holes_sorted)
    for rank, pos in enumerate(complement_sorted):
        slot[pos] = n_holes + rank

    k4_slots = [slot[p] for p in K4_POSITIONS]
    order = sorted(range(97), key=lambda j: k4_slots[j])
    return "".join(K4_CARVED[order[i]] for i in range(97))


def try_real_ct(real_ct97, label="", threshold=-5.5):
    """Try all keyword×cipher×alpha on a 97-char candidate real CT."""
    best_sc, best = -1e9, None
    for key in KEYWORDS:
        for aname, alpha in [("KA", KA), ("AZ", AZ)]:
            for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cfn(real_ct97, key, alpha)
                except Exception:
                    continue
                sc = score_text_per_char(pt)
                cribs = has_cribs(pt)
                if cribs:
                    print(f"\n  ★★★ CRIB HIT! [{label}] {cname}/{key}/{aname}")
                    print(f"      real_ct[:40]: {real_ct97[:40]}")
                    print(f"      PT:      {pt}")
                    return {"score": sc, "pt": pt, "key": key, "alpha": aname,
                            "cipher": cname, "crib": cribs, "real_ct": real_ct97,
                            "label": label}
                if sc > best_sc:
                    best_sc = sc
                    best = {"score": sc, "pt": pt, "key": key, "alpha": aname,
                            "cipher": cname, "crib": [], "real_ct": real_ct97,
                            "label": label}
    return best if (best and best_sc > threshold) else None


RESULTS = []  # (score, name, result_dict)

def eval_mask(holes_set, name):
    """Evaluate a mask: compute K4 real CT, try decryption, record if interesting."""
    if not holes_set:
        return
    n_k4_holes = sum(1 for p in K4_POSITIONS if p in holes_set)
    if n_k4_holes == 0 or n_k4_holes == 97:
        return  # degenerate: all holes or all complement → trivial natural order
    real_ct = mask_to_k4_real_ct(holes_set)
    res = try_real_ct(real_ct, name)
    if res:
        sc = res["score"]
        RESULTS.append((sc, name, res))
        tag = "★ CRIB" if res["crib"] else ""
        print(f"  {tag} {name}: score={sc:.3f} [{res['key']}/{res['alpha']}/{res['cipher']}]  k4holes={n_k4_holes}/97")
        print(f"    PT[:70]: {res['pt'][:70]}")


# ═══════════════════════════════════════════════════════════════════════
# APPROACH A: AZ→KA Cycle-Based Masks
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH A: AZ→KA Cycle-Based Masks")
print("="*70)

# A1-A4: letter at each cell (cipher or tableau) → cycle → hole
for src_name, get_ch in [
    ("cipher",  lambda r, c: GRID[r][c]),
    ("tableau", lambda r, c: TABLEAU[r][c]),
]:
    for hole_cyc, hname in [(CYCLE_17, "17"), (CYCLE_8, "8")]:
        holes = set()
        for r in range(NROWS):
            for c in range(NCOLS):
                ch = get_ch(r, c)
                if ch.isalpha() and ch in hole_cyc:
                    holes.add(r * NCOLS + c)
        name = f"A_{src_name}_cyc{hname}"
        print(f"  {name}: {len(holes)} holes ({100*len(holes)/868:.1f}%)")
        eval_mask(holes, name)

# A5: Column-based mask: cell (r,c) is hole if TABLEAU[0][c] (header) ∈ hole_cycle
for hole_cyc, hname in [(CYCLE_17, "17"), (CYCLE_8, "8")]:
    holes = set()
    for r in range(NROWS):
        for c in range(NCOLS):
            hch = TABLEAU[0][c]
            if hch.isalpha() and hch in hole_cyc:
                holes.add(r * NCOLS + c)
    name = f"A_col_header_cyc{hname}"
    print(f"  {name}: {len(holes)} holes ({100*len(holes)/868:.1f}%)")
    eval_mask(holes, name)

# A6: Row-based mask: cell (r,c) is hole if TABLEAU[r][0] (key letter) ∈ hole_cycle
for hole_cyc, hname in [(CYCLE_17, "17"), (CYCLE_8, "8")]:
    holes = set()
    for r in range(NROWS):
        kch = TABLEAU[r][0]
        if kch.isalpha() and kch in hole_cyc:
            for c in range(NCOLS):
                holes.add(r * NCOLS + c)
    name = f"A_row_keylet_cyc{hname}"
    print(f"  {name}: {len(holes)} holes ({100*len(holes)/868:.1f}%)")
    eval_mask(holes, name)

# A7: XOR mask: hole if cipher_cycle != tableau_cycle (one 17, other 8)
holes_xor = set()
for r in range(NROWS):
    for c in range(NCOLS):
        cch = GRID[r][c]
        tch = TABLEAU[r][c]
        cc = 17 if cch in CYCLE_17 else (8 if cch in CYCLE_8 else 0)
        tc = 17 if tch in CYCLE_17 else (8 if tch in CYCLE_8 else 0)
        if cc != tc and cc != 0 and tc != 0:
            holes_xor.add(r * NCOLS + c)
name = "A_cipher_tab_cycle_XOR"
print(f"  {name}: {len(holes_xor)} holes ({100*len(holes_xor)/868:.1f}%)")
eval_mask(holes_xor, name)

# ═══════════════════════════════════════════════════════════════════════
# APPROACH B: Row-Key × Col-Header Product Masks
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH B: Row-Key × Col-Header Product Masks")
print("="*70)

def build_product_mask(row_cycs, col_cycs, mode="both"):
    """
    mode="both": hole if row_key ∈ row_cycs AND col_header ∈ col_cycs
    mode="xor":  hole if exactly one of row/col condition holds
    mode="either": hole if either row or col condition holds
    """
    row_cycs = frozenset().union(*row_cycs)
    col_cycs = frozenset().union(*col_cycs)
    holes = set()
    for r in range(1, 27):  # body rows only (rows 1-26)
        kl = TABLEAU[r][0]
        row_ok = kl in row_cycs
        for c in range(1, 31):  # body cols only (cols 1-30)
            hl = TABLEAU[0][c]
            if not hl.isalpha():
                continue
            col_ok = hl in col_cycs
            if mode == "both":
                cond = row_ok and col_ok
            elif mode == "xor":
                cond = row_ok != col_ok
            else:
                cond = row_ok or col_ok
            if cond:
                holes.add(r * NCOLS + c)
    return holes

combos_B = [
    ([CYCLE_17], [CYCLE_17], "both",   "B_r17_c17_both"),
    ([CYCLE_17], [CYCLE_8],  "both",   "B_r17_c8_both"),
    ([CYCLE_8],  [CYCLE_17], "both",   "B_r8_c17_both"),
    ([CYCLE_8],  [CYCLE_8],  "both",   "B_r8_c8_both"),
    ([CYCLE_17], [CYCLE_17], "xor",    "B_r17_c17_xor"),
    ([CYCLE_8],  [CYCLE_8],  "xor",    "B_r8_c8_xor"),
    ([CYCLE_17, CYCLE_8], [CYCLE_17, CYCLE_8], "xor", "B_r178_c178_xor"),
    ([CYCLE_17], [CYCLE_17], "either", "B_r17_c17_either"),
]
for rc, cc, mode, name in combos_B:
    h = build_product_mask(rc, cc, mode)
    print(f"  {name}: {len(h)} holes ({100*len(h)/868:.1f}%)")
    eval_mask(h, name)

# ═══════════════════════════════════════════════════════════════════════
# APPROACH C: Overlay Difference Mask (cipher != tableau)
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH C: Cipher ≠ Tableau Difference Mask")
print("="*70)

differ_set = set()
match_set  = set()
for r in range(NROWS):
    for c in range(NCOLS):
        cp, tb = GRID[r][c], TABLEAU[r][c]
        if cp.isalpha() and tb.isalpha() and cp != 'X' and tb != ' ':
            pos = r * NCOLS + c
            (match_set if cp == tb else differ_set).add(pos)

print(f"  cipher != tableau (C_differ): {len(differ_set)} holes")
print(f"  cipher == tableau (C_match):  {len(match_set)} holes")
eval_mask(differ_set, "C_differ")
eval_mask(match_set,  "C_match")

# K3 region: how many match positions?
k3_matches = [p for p in match_set if 14*31 <= p < 24*31 + 26]
k4_matches = [p for p in match_set if p in set(K4_POSITIONS)]
print(f"  K3-region matches: {len(k3_matches)}")
print(f"  K4-region matches: {len(k4_matches)}")
if k4_matches:
    print(f"  K4 match positions: {[K4_POSITIONS.index(p) for p in k4_matches]}")

# ═══════════════════════════════════════════════════════════════════════
# APPROACH D: Letter-Index Reading Order (rank by KA/AZ position)
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH D: Letter-Index Reading Order (no binary mask)")
print("="*70)

for src_name, get_ch in [
    ("cipher",  lambda j: GRID[K4_POSITIONS[j]//31][K4_POSITIONS[j]%31]),
    ("tableau", lambda j: TABLEAU[K4_POSITIONS[j]//31][K4_POSITIONS[j]%31]),
]:
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        for rev_name, reverse in [("fwd", False), ("rev", True)]:
            def key_fn(j, _alpha=alpha, _get=get_ch):
                ch = _get(j)
                return _alpha.index(ch) if (ch.isalpha() and ch in _alpha) else 99
            order = sorted(range(97), key=key_fn, reverse=reverse)
            real_ct = "".join(K4_CARVED[order[i]] for i in range(97))
            name = f"D_{src_name}_{alpha_name}_{rev_name}"
            res = try_real_ct(real_ct, name)
            if res:
                RESULTS.append((res["score"], name, res))
                print(f"  {name}: {res['score']:.3f} [{res['key']}/{res['alpha']}/{res['cipher']}]")
                print(f"    PT[:70]: {res['pt'][:70]}")

# ═══════════════════════════════════════════════════════════════════════
# APPROACH E: Period-8 Structural Mask (Extra-L/T Anomaly)
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH E: Period-8 / Extra-L/T Anomaly Mask")
print("="*70)

# Row N (14) has extra L, row V (22) has extra T. V-N = T-L = 8.
# Candidate hole rows: multiples of 8 offset from 14 (rows 6, 14, 22)
# Also: row 0 and row 27 (header/footer) might be special

# E1: rows at positions 6, 14, 22 (center and ±8)
p8_special_rows = {6, 14, 22}
holes_e1 = {r*NCOLS+c for r in p8_special_rows for c in range(NCOLS)}
print(f"  E1_p8rows (6,14,22): {len(holes_e1)} holes")
eval_mask(holes_e1, "E1_p8rows_6_14_22")

# E2: cols where header = L or T (the anomalous extra chars)
l_t_cols = {c for c in range(NCOLS) if TABLEAU[0][c] in ('L', 'T')}
holes_e2 = {r*NCOLS+c for r in range(NROWS) for c in l_t_cols}
print(f"  E2_LT_header_cols (cols {sorted(l_t_cols)}): {len(holes_e2)} holes")
eval_mask(holes_e2, "E2_LT_cols")

# E3: period-8 row mask × 8-cycle col mask (combined)
holes_e3 = {r*NCOLS+c for r in p8_special_rows
            for c in range(1, 31)
            if TABLEAU[0][c].isalpha() and TABLEAU[0][c] in CYCLE_8}
print(f"  E3_p8rows×8cyc_cols: {len(holes_e3)} holes")
eval_mask(holes_e3, "E3_p8rows_x_8cyccols")

# E4: every 8th row (rows 0,8,16,24) — another period-8 interpretation
holes_e4 = {r*NCOLS+c for r in range(0, NROWS, 8) for c in range(NCOLS)}
print(f"  E4_every8_rows (0,8,16,24): {len(holes_e4)} holes")
eval_mask(holes_e4, "E4_every8_rows")

# E5: L+T = 30 = body width. Use cols sum-30: col L(12) + col T(20) = 32 → col indices
# Col with L at header: header[c]=L → c where AZ[(c-1)%26]='L' → c=12 (L=11+1 in 1-indexed)
l_col = next(c for c in range(NCOLS) if TABLEAU[0][c] == 'L')
t_col = next(c for c in range(NCOLS) if TABLEAU[0][c] == 'T')
print(f"  Header L at col {l_col}, T at col {t_col}, sum={l_col+t_col}, diff={t_col-l_col}")

# ═══════════════════════════════════════════════════════════════════════
# APPROACH F: AZ-pos vs KA-pos Comparison Binary Signal
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH F: AZ-pos vs KA-pos Comparison Signal")
print("="*70)

# For each row r: key_letter K. AZ_pos(K)=i, KA_pos(K)=KA.index(K).
# Signal: AZ_pos > KA_pos → "hole row"
# For each col c: header letter H. AZ_pos(H) vs KA_pos(H).

row_azgtka = set()
row_kalgta = set()
for r in range(1, 27):
    kl = TABLEAU[r][0]
    az_p = AZ.index(kl)
    ka_p = KA.index(kl)
    if az_p > ka_p:
        row_azgtka.add(r)
    else:
        row_kalgta.add(r)

col_azgtka = set()
col_kalgta = set()
for c in range(1, 31):
    hl = TABLEAU[0][c]
    if hl.isalpha():
        az_p = AZ.index(hl)
        ka_p = KA.index(hl)
        if az_p > ka_p:
            col_azgtka.add(c)
        else:
            col_kalgta.add(c)

print(f"  F_row_AZ>KA: {len(row_azgtka)} rows = {sorted(row_azgtka)}")
print(f"  F_row_KA>AZ: {len(row_kalgta)} rows")
print(f"  F_col_AZ>KA: {len(col_azgtka)} cols")
print(f"  F_col_KA>AZ: {len(col_kalgta)} cols")

for rset, rname in [(row_azgtka, "AZ>KA"), (row_kalgta, "KA>AZ")]:
    for cset, cname in [(col_azgtka, "AZ>KA"), (col_kalgta, "KA>AZ")]:
        # Product mask: hole if BOTH row and col satisfy their condition
        holes_f = {r*NCOLS+c for r in rset for c in cset if 1 <= c <= 30}
        name = f"F_r{rname}_c{cname}_product"
        print(f"  {name}: {len(holes_f)} holes")
        eval_mask(holes_f, name)

# Row-only and col-only variants
holes_row_AZ = {r*NCOLS+c for r in row_azgtka for c in range(NCOLS)}
holes_col_AZ = {r*NCOLS+c for c in col_azgtka for r in range(NROWS)}
eval_mask(holes_row_AZ, "F_rowonly_AZ>KA")
eval_mask(holes_col_AZ, "F_colonly_AZ>KA")

# ═══════════════════════════════════════════════════════════════════════
# APPROACH G: K3 Reading-Order Step Pattern → K4
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH G: K3 Step Pattern → K4 (mod 97)")
print("="*70)

# K3's dominant reading-order step in K3-internal space (= global linear for K3).
# Apply dominant step(s) mod 97 to K4's 97 positions.
# Since 97 is prime, all non-zero steps generate the full group.

best_g_sc = -1e9
best_g_info = None

# Try all K3 top steps mapped to mod 97
tried_steps = set()
for dom_step, cnt in k3_top_steps:
    ds97 = dom_step % 97
    if ds97 == 0 or ds97 in tried_steps:
        continue
    tried_steps.add(ds97)
    # Also try the complement step (97 - ds97)
    for step in [ds97, 97 - ds97]:
        step = step % 97
        if step == 0 or step in tried_steps:
            continue
        tried_steps.add(step)
        for start in range(97):
            # Build cyclic permutation: reading slot j ← K4 internal position (start + j*step)%97
            order = [(start + j * step) % 97 for j in range(97)]
            real_ct = "".join(K4_CARVED[order[i]] for i in range(97))
            res = try_real_ct(real_ct, f"G_step{step}_s{start}")
            if res and res["score"] > best_g_sc:
                best_g_sc = res["score"]
                best_g_info = (step, start, res)
            if res and (res["score"] > -5.5 or res["crib"]):
                RESULTS.append((res["score"], f"G_step{step}_s{start}", res))
                print(f"  G_step={step} start={start}: {res['score']:.3f} [{res['key']}/{res['alpha']}/{res['cipher']}]")

if best_g_info:
    step, start, res = best_g_info
    print(f"  Best G: step={step} start={start} score={res['score']:.3f}")
else:
    print(f"  G: no results above threshold")

# ═══════════════════════════════════════════════════════════════════════
# APPROACH H: 180°-Valid Grilles from Structural Seeds
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH H: 180°-Valid Grilles (conflict resolution)")
print("="*70)

# Under 180° rotation: linear pos p ↔ pos (867-p) [verified: (r,c)→(27-r,30-c) = 867-p]
def make_180_valid(seed_holes, prefer_lower=True):
    """Force 180°-validity: for each conflict {p, 867-p}, keep only one."""
    result = set()
    paired = set()
    for pos in sorted(seed_holes):
        if pos in paired:
            continue
        partner = 867 - pos
        if partner in seed_holes:
            # Conflict: keep the lower-index one (or higher based on prefer_lower)
            keep = pos if prefer_lower else partner
            result.add(keep)
        else:
            result.add(pos)
        paired.add(pos)
        paired.add(partner)
    return result

# Generate seeds from all Approach-A masks and make 180°-valid
seed_masks = {
    "A_cipher17": {r*NCOLS+c for r in range(NROWS) for c in range(NCOLS)
                   if GRID[r][c].isalpha() and GRID[r][c] in CYCLE_17},
    "A_cipher8":  {r*NCOLS+c for r in range(NROWS) for c in range(NCOLS)
                   if GRID[r][c].isalpha() and GRID[r][c] in CYCLE_8},
    "A_tab17":    {r*NCOLS+c for r in range(NROWS) for c in range(NCOLS)
                   if TABLEAU[r][c].isalpha() and TABLEAU[r][c] in CYCLE_17},
    "C_differ":   differ_set,
    "B_r17_c8":   build_product_mask([CYCLE_17], [CYCLE_8], "both"),
}

for sname, seed in seed_masks.items():
    for prefer_lower in [True, False]:
        valid = make_180_valid(seed, prefer_lower)
        n_v = len(valid)
        conflicts = sum(1 for p in valid if (867-p) in valid)
        pref_str = "lo" if prefer_lower else "hi"
        name = f"H_{sname}_{pref_str}_180v"
        print(f"  {name}: {n_v} holes (target 434), conflicts={conflicts}")
        if conflicts == 0 and 300 <= n_v <= 600:
            eval_mask(valid, name)

# ═══════════════════════════════════════════════════════════════════════
# APPROACH I: NOVEL — Combined Structural Score → Top-434 Grille
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH I: Novel Combined-Score Grille (top 434 by structure)")
print("="*70)

def score_cell(r, c):
    """Multi-factor structural score for a cell."""
    kl = TABLEAU[r][0]  # key letter
    hl = TABLEAU[0][c]  # header letter
    cph = GRID[r][c]    # cipher letter

    # Factor 1: AZ-pos vs KA-pos difference for row key letter
    f1 = (AZ.index(kl) - KA.index(kl)) % 26 if kl.isalpha() else 0
    # Factor 2: AZ-pos vs KA-pos difference for column header letter
    f2 = (AZ.index(hl) - KA.index(hl)) % 26 if hl.isalpha() else 0
    # Factor 3: cycle of cipher letter (17=high, 8=medium, 0=low, Z=0)
    f3 = 2 if cph in CYCLE_17 else (1 if cph in CYCLE_8 else 0)
    # Factor 4: cycle of tableau letter
    tl = TABLEAU[r][c]
    f4 = 2 if tl in CYCLE_17 else (1 if tl in CYCLE_8 else 0)
    return (f1 + f2) * 4 + f3 + f4

all_cells = [(r*NCOLS+c, score_cell(r, c)) for r in range(NROWS) for c in range(NCOLS)]
all_cells.sort(key=lambda x: x[1], reverse=True)

for n_target in [434, 400, 468, 350, 500]:
    seed = {p for p, _ in all_cells[:n_target]}
    # Check 180° validity
    conflicts = sum(1 for p in seed if (867-p) in seed)
    name = f"I_combined_top{n_target}"
    print(f"  {name}: {n_target} holes, {conflicts//2} 180°-conflicts")
    eval_mask(seed, name)
    # Make 180° valid
    valid = make_180_valid(seed)
    if len(valid) != n_target:
        eval_mask(valid, f"{name}_180v")

# ═══════════════════════════════════════════════════════════════════════
# APPROACH J: K3 TRANSPOSITION DIRECTLY APPLIED AS K4 PERMUTATION
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH J: K3 Transposition Formula Extended to K4")
print("="*70)

# K3 formula: k3_perm_formula(i) for i in 0..335.
# If K4 uses THE SAME formula but applied to K4's 97 positions
# (treating K4 as positions 337..433 in the bottom half):
# K4 internal index: 0..96 → bottom-half position 337+i (skipping gap at 336)
# Try applying k3_perm_formula to K4 internal positions 337..433:
# j_k4 = 337 + k4_idx (skipping the ? at 336)

for k4_offset in [336, 337, 338]:
    sigma = []
    valid = True
    for k4_idx in range(97):
        j = k4_offset + k4_idx
        if j >= 336:
            # Apply formula beyond its designed range (mod 336? or raw?)
            raw = k3_perm_formula(j % 336)
            # Map raw (0..335) to k4 space (0..96) if possible
            if raw >= k4_offset and raw < k4_offset + 97:
                sigma.append(raw - k4_offset)
            else:
                valid = False
                break
    if valid and len(sigma) == 97 and len(set(sigma)) == 97:
        real_ct = "".join(K4_CARVED[sigma[i]] for i in range(97))
        name = f"J_k3formula_off{k4_offset}"
        res = try_real_ct(real_ct, name)
        if res:
            RESULTS.append((res["score"], name, res))
            print(f"  {name}: score={res['score']:.3f}")

# ═══════════════════════════════════════════════════════════════════════
# APPROACH K: MISSPELLING SIGNAL — KA-cycle positions 56, 89 as SEEDS
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH K: Misspelling positions (K=PT56→CT56, A=PT10→CT89)")
print("="*70)

# K1 IQLUSION: PT[56]→CT[56]=K. K is in CYCLE_17.
# K3 DESPARATLY: PT[10]→CT[89]=A. A is in CYCLE_17.
# Both misspelling CT positions give letters in CYCLE_17.
# This might reinforce that CYCLE_17 → HOLES.
# Also: position 56 in K1 (top half) → linear 56 in 28×31
# Position 89 in K3 (bottom half) → K3-internal 89 → linear 434+89=523

# Test: what if the grille is defined so that linear positions corresponding
# to the misspelling CT chars are HOLES? (56 and 523 are holes)
# We can't do much with just 2 seeds, but we can examine what mask gives
# both 56 and 523 as holes.
# Both are in CYCLE_17 (cipher letter K and A respectively), so A_cipher17 already covers them.
k1_misspell_linear = 56
k3_misspell_linear = 434 + 89  # K3-internal 89 → linear
print(f"  K1 misspell position: linear {k1_misspell_linear} = row {k1_misspell_linear//31} col {k1_misspell_linear%31}")
print(f"  K3 misspell position: linear {k3_misspell_linear} = row {k3_misspell_linear//31} col {k3_misspell_linear%31}")
print(f"  K1 cipher letter: {GRID[k1_misspell_linear//31][k1_misspell_linear%31]} (cycle: {'17' if GRID[k1_misspell_linear//31][k1_misspell_linear%31] in CYCLE_17 else '8'})")
print(f"  K3 cipher letter: {GRID[k3_misspell_linear//31][k3_misspell_linear%31]} (cycle: {'17' if GRID[k3_misspell_linear//31][k3_misspell_linear%31] in CYCLE_17 else '8'})")

# ═══════════════════════════════════════════════════════════════════════
# BONUS: Verify K3 is pure transposition, examine step structure
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("BONUS: K3 Reading Order Structure (for geometric insight)")
print("="*70)

# K3_INV[j] = K3 internal position read at slot j
# As (row, col) in 28×31 grid: = (14 + K3_INV[j]//31, K3_INV[j]%31) for K3_INV[j]<310
# else (24, K3_INV[j]-310)
print("K3 reading order, first 30 slots:")
for j in range(30):
    i = K3_INV[j]
    if i < 310:
        r, c = 14 + i//31, i%31
    else:
        r, c = 24, i-310
    lin = r*31 + c
    print(f"  slot {j:3d}: K3_internal={i:3d} → grid({r},{c:2d}) linear={lin}")

# Row sequence in reading order
rows_seq = []
for j in range(336):
    i = K3_INV[j]
    r = (14 + i//31) if i < 310 else 24
    rows_seq.append(r)
print(f"\nRow values in K3 reading order (first 50): {rows_seq[:50]}")
print(f"Col values in K3 reading order (first 50):")
col_seq = []
for j in range(336):
    i = K3_INV[j]
    c = i%31 if i < 310 else i-310
    col_seq.append(c)
print(f"  {col_seq[:50]}")

# Does the reading order visit rows in any pattern?
row_counter = Counter(rows_seq)
print(f"Row visit counts: {sorted(row_counter.items())}")

# Step pattern: what columns are read in sequence within each row?
# Group slots by row
row_slots = {}
for j in range(336):
    i = K3_INV[j]
    r = (14 + i//31) if i < 310 else 24
    c = i%31 if i < 310 else i-310
    row_slots.setdefault(r, []).append((j, c))
print("\nColumn reading order within each row (first few):")
for r in sorted(row_slots)[:5]:
    slots = row_slots[r]
    slots.sort(key=lambda x: x[0])  # sort by reading order slot
    print(f"  Row {r}: cols in reading order = {[c for j,c in slots[:15]]}")

# ═══════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("FINAL SUMMARY")
print("="*70)

RESULTS.sort(reverse=True, key=lambda x: x[0])
crib_hits = [(sc, nm, r) for sc, nm, r in RESULTS if r.get("crib")]
non_crib = [(sc, nm, r) for sc, nm, r in RESULTS if not r.get("crib")]

if crib_hits:
    print(f"\n★★★ CRIB HITS ({len(crib_hits)}):")
    for sc, nm, r in crib_hits:
        print(f"  [{nm}] score={sc:.3f} {r['key']}/{r['alpha']}/{r['cipher']}")
        print(f"    PT: {r['pt']}")
else:
    print("No crib hits.")

print(f"\nTop non-crib results ({min(15, len(non_crib))} of {len(non_crib)}):")
for sc, nm, r in non_crib[:15]:
    print(f"  score={sc:.3f} [{nm}] {r['key']}/{r['alpha']}/{r['cipher']}")
    print(f"    PT[:70]: {r['pt'][:70]}")

# K3 step summary
print(f"\nK3 top steps: {k3_top_steps}")
print(f"K4 analog (mod 97): {[(s%97, c) for s,c in k3_top_steps]}")
print(f"\n17-cycle: {''.join(sorted(CYCLE_17))}")
print(f"8-cycle:  {''.join(sorted(CYCLE_8))}")
print(f"Fixed:    Z")
print(f"\nK3 pure-transposition check: {mismatches_pure if len(K3_CT)==336 else 'K3_CT wrong length'}/336 mismatches")
