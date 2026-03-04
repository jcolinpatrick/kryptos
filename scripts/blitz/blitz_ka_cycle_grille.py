#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_ka_cycle_grille.py

Tests AZ->KA permutation cycle structure as Cardan grille for K4.
Approaches A-G from mission brief.

PYTHONPATH=src python3 -u scripts/blitz_ka_cycle_grille.py
"""

import sys
sys.path.insert(0, 'scripts')

from kbot_harness import (
    load_quadgrams, score_text, score_text_per_char, has_cribs,
    vig_decrypt, beau_decrypt, test_perm, test_unscramble,
    K4_CARVED, AZ, KA, KEYWORDS, CRIBS,
)

# ── AZ->KA permutation & cycles ──────────────────────────────────────────────

perm = {AZ[i]: KA[i] for i in range(26)}   # A->K, B->R, ...

def get_cycles(perm_dict, alpha):
    seen, cycles = set(), []
    for start in alpha:
        if start not in seen:
            cyc = []
            c = start
            while c not in seen:
                seen.add(c); cyc.append(c); c = perm_dict[c]
            cycles.append(tuple(cyc))
    return sorted(cycles, key=len, reverse=True)

CYCLES = get_cycles(perm, AZ)
C17 = set(CYCLES[0])   # 17-cycle
C8  = set(CYCLES[1])   # 8-cycle
CZ  = set(CYCLES[2])   # fixed: {Z}

L_CYCLE = {}   # letter -> cycle index (0=17-cyc, 1=8-cyc, 2=Z)
L_POS   = {}   # letter -> position within its cycle
for ci, cyc in enumerate(CYCLES):
    for pi, letter in enumerate(cyc):
        L_CYCLE[letter] = ci; L_POS[letter] = pi

print("AZ->KA Cycles:")
for cyc in CYCLES:
    print(f"  {len(cyc)}-cycle: {''.join(cyc)}")
print(f"C17 ({len(C17)}): {sorted(C17)}")
print(f"C8  ({len(C8)}): {sorted(C8)}")
print(f"CZ  ({len(CZ)}): {sorted(CZ)}")

# ── Cipher grid (28×31) ───────────────────────────────────────────────────────

_CG = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",   # row 0  K1
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",   # row 1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",   # row 2
    "EGGWHKK.DQMCPFQZDQMMIAGPFXHQRLG",  # row 3  (. = ? unknown)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # row 4
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",   # row 5
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",   # row 6
    "IHHDDDUVH.DWKBFUFPWNTDFIYCUQZER",   # row 7
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",   # row 8
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",   # row 9
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",   # row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",   # row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",   # row 13
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",   # row 14  K3 start (CENTER)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # row 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",   # row 17
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",   # row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",   # row 19
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",   # row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",   # row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",   # row 22
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",   # row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW.OBKR",   # row 24  K4 at col 27-30 (. at 26)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",   # row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",   # row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",   # row 27
]
for i, r in enumerate(_CG):
    assert len(r) == 31, f"Cipher row {i} has {len(r)} chars"

def cg(r, c):
    ch = _CG[r][c]
    return None if ch == '.' else ch

# ── KA Vigenere Tableau (28×31) ───────────────────────────────────────────────

def gen_tableau():
    hdr = ' ' + (AZ * 2)[:30]     # ' ABCDEFGHIJKLMNOPQRSTUVWXYZABCD'
    rows = [hdr]
    for i in range(26):
        body = (KA * 3)[i:i+30]   # KA shifted by i, 30 chars
        rows.append(AZ[i] + body)
    rows.append(hdr)
    for i, r in enumerate(rows):
        assert len(r) == 31, f"Tableau row {i} len={len(r)}"
    return rows

TAB = gen_tableau()

def tg(r, c):
    ch = TAB[r][c]
    return None if ch == ' ' else ch

# Note on Row N (row 14, key=N): the physical tableau has an EXTRA L making it
# 32 chars. We truncate to 31 here. The extra L is a structural anomaly explored
# separately.

# Verify key column
keycol = ''.join(TAB[i][0] for i in range(1, 27))
assert keycol == AZ, f"Key column mismatch: {keycol}"
print(f"\nTableau key column: {keycol} ✓")

# ── K4 and K3 positions ───────────────────────────────────────────────────────

K4_POS = [(24, c) for c in range(27, 31)] + \
         [(r, c) for r in range(25, 28) for c in range(31)]
assert len(K4_POS) == 97
k4_from_grid = ''.join(cg(r, c) for r, c in K4_POS)
assert k4_from_grid == K4_CARVED, f"K4 mismatch: {k4_from_grid}"
print(f"K4 grid: VERIFIED (97 positions)")

K3_POS = [(r, c) for r in range(14, 24) for c in range(31)] + \
         [(24, c) for c in range(26)]
assert len(K3_POS) == 336
K3_CT = ''.join(cg(r, c) for r, c in K3_POS if cg(r, c) is not None)
# Full K3 PT (Carter tomb, 336 chars)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATEN"
    "CUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLING"
    "HANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDE"
    "NINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIR"
    "ESCAPINGFROMTHECHAMBER"
)
print(f"K3 CT length: {len(K3_CT)}, PT prefix: {K3_PT[:30]}")

# ── Mask constructors ─────────────────────────────────────────────────────────

def mask_by_letter_set(hole_set, source='cipher'):
    """1=hole if cell letter ∈ hole_set. source='cipher'|'tableau'."""
    m = []
    for r in range(28):
        row = []
        for c in range(31):
            letter = cg(r, c) if source == 'cipher' else tg(r, c)
            row.append(1 if (letter and letter in hole_set) else 0)
        m.append(row)
    return m

def mask_by_parity(source='cipher', parity=0):
    """1=hole if position-within-cycle % 2 == parity."""
    m = []
    for r in range(28):
        row = []
        for c in range(31):
            letter = cg(r, c) if source == 'cipher' else tg(r, c)
            row.append(1 if (letter and L_POS.get(letter, 0) % 2 == parity) else 0)
        m.append(row)
    return m

def mask_by_cycle_index(source='cipher', hole_cycle_indices=frozenset({0})):
    """1=hole if letter's cycle index ∈ hole_cycle_indices."""
    m = []
    for r in range(28):
        row = []
        for c in range(31):
            letter = cg(r, c) if source == 'cipher' else tg(r, c)
            row.append(1 if (letter and L_CYCLE.get(letter, -1) in hole_cycle_indices) else 0)
        m.append(row)
    return m

def mask_diff_cipher_tableau(hole_set):
    """Approach F: diff = AZ[(KA_idx(cipher) - KA_idx(tableau)) % 26] ∈ hole_set."""
    m = []
    for r in range(28):
        row = []
        for c in range(31):
            cp = cg(r, c); tp = tg(r, c)
            if cp and tp and cp in KA and tp in KA:
                diff_letter = AZ[(KA.index(cp) - KA.index(tp)) % 26]
                row.append(1 if diff_letter in hole_set else 0)
            else:
                row.append(0)
        m.append(row)
    return m

def mask_rowkey(hole_set):
    """Approach E: key-column letter of each tableau row → entire row is hole/solid."""
    m = []
    for r in range(28):
        key = TAB[r][0]
        val = 1 if (key != ' ' and key in hole_set) else 0
        m.append([val] * 31)
    return m

def mask_perm_power(n, thresh_set, source='cipher'):
    """Approach C: letters whose perm^n lands in thresh_set → holes."""
    hole_letters = set()
    for letter in AZ:
        c = letter
        for _ in range(n % 136):
            c = perm[c]
        if c in thresh_set:
            hole_letters.add(letter)
    return mask_by_letter_set(hole_letters, source)

# ── Utility ───────────────────────────────────────────────────────────────────

def mask_stats(mask):
    total = sum(mask[r][c] for r in range(28) for c in range(31))
    k4    = sum(mask[r][c] for r, c in K4_POS)
    return total, k4

def rot180_valid_pairs(mask):
    """Count pairs (r,c)+(27-r,30-c) with exactly one hole (valid grille pairs)."""
    return sum(1 for r in range(14) for c in range(31)
               if mask[r][c] + mask[27-r][30-c] == 1)

def build_sigmas(mask):
    """
    Build list of (sigma, description) to test.
    sigma[j] = original K4_CARVED index, so real_CT[j] = K4_CARVED[sigma[j]].
    """
    h_idx = [i for i, (r, c) in enumerate(K4_POS) if mask[r][c]]
    s_idx = [i for i, (r, c) in enumerate(K4_POS) if not mask[r][c]]
    sigmas = []

    # Primary: holes first, then solids
    sigmas.append((h_idx + s_idx, "holes-first"))
    # Complement: solids first, then holes
    sigmas.append((s_idx + h_idx, "solids-first"))

    # 180°-rotation reading:
    # K4 cells visible in position 1 (mask hole): read first
    # K4 cells visible in position 2 (180° rotation of a hole in position 1):
    #   cell (r,c) visible in pos2 iff mask[27-r][30-c] == 1 (its pair is a hole)
    pos2 = [i for i, (r, c) in enumerate(K4_POS)
            if not mask[r][c] and mask[27-r][30-c] == 1]
    # Remaining (cells whose 180° pair is ALSO solid or unknown)
    covered = set(h_idx) | set(pos2)
    remain  = [i for i in range(97) if i not in covered]
    sigmas.append((h_idx + pos2 + remain, "rot180"))

    # Reverse reading (pos2 first, then pos1)
    sigmas.append((pos2 + h_idx + remain, "rot180-inv"))

    return sigmas

# ── Run all masks ─────────────────────────────────────────────────────────────

ALL_RESULTS = []
GLOBAL_BEST_SCORE = -999999

def run_mask(name, mask, verbose=True):
    global GLOBAL_BEST_SCORE
    total, k4_h = mask_stats(mask)
    rv = rot180_valid_pairs(mask)

    best_sc = -999999
    best_row = None

    for sigma, sig_label in build_sigmas(mask):
        r = test_perm(sigma)
        if r is None:
            continue
        sc = r['score']
        pc = r.get('score_per_char', sc / max(1, 94))

        if r.get('crib_hit'):
            print(f"\n{'!'*70}")
            print(f"!!! CRIB HIT: {name}/{sig_label}")
            print(f"Key={r['key']} Cipher={r['cipher']} Alpha={r['alpha']}")
            print(f"PT={r['pt']}")
            print(f"ENE@21={r.get('ene_at_21')} BC@63={r.get('bc_at_63')}")
            print(f"ENE_any={r.get('ene_anywhere')} BC_any={r.get('bc_anywhere')}")
            print(f"{'!'*70}")

        if sc > best_sc:
            best_sc = sc
            best_row = {'name': f"{name}/{sig_label}", 'k4': k4_h, 'total': total,
                        'score': sc, 'pc': pc, 'key': r['key'], 'cipher': r['cipher'],
                        'alpha': r['alpha'], 'pt': r['pt'][:60], 'crib': r.get('crib_hit', False)}

        ALL_RESULTS.append({'name': f"{name}/{sig_label}", 'k4': k4_h, 'total': total,
                            'score': sc, 'pc': pc, 'key': r['key'], 'cipher': r['cipher'],
                            'alpha': r['alpha'], 'pt': r['pt'][:60], 'crib': r.get('crib_hit', False)})
        if sc > GLOBAL_BEST_SCORE:
            GLOBAL_BEST_SCORE = sc

    if verbose and best_row:
        print(f"  {name}: total={total}/868 k4={k4_h}/97 rot180_valid={rv}/434 "
              f"best={best_sc:.1f} ({best_row['pc']:.2f}/q) "
              f"key={best_row['key']} {best_row['cipher']}/{best_row['alpha']} | "
              f"{best_row['pt'][:40]}"
              + (" *** CRIB ***" if best_row['crib'] else ""))

# ── A: Cipher letter → cycle membership ─────────────────────────────────────

print("\n" + "="*70)
print("A: Cipher letter → cycle membership")
print("="*70)
for hole_set, label in [
    (C17,       "17cyc"),
    (C8,        "8cyc"),
    (CZ,        "Z-fixed"),
    (C17 | CZ,  "17+Z"),
    (C8  | CZ,  "8+Z"),
]:
    run_mask(f"A-cipher-{label}", mask_by_letter_set(hole_set, 'cipher'))

# ── D: Tableau letter → cycle membership ─────────────────────────────────────

print("\n" + "="*70)
print("D: Tableau letter → cycle membership")
print("="*70)
for hole_set, label in [
    (C17,       "17cyc"),
    (C8,        "8cyc"),
    (C17 | CZ,  "17+Z"),
    (C8  | CZ,  "8+Z"),
]:
    run_mask(f"D-tableau-{label}", mask_by_letter_set(hole_set, 'tableau'))

# ── B: Cycle position parity ──────────────────────────────────────────────────

print("\n" + "="*70)
print("B: Cycle position parity (even/odd within cycle)")
print("="*70)
for src in ['cipher', 'tableau']:
    for par in [0, 1]:
        run_mask(f"B-{src}-par{par}", mask_by_parity(src, par))

# ── E: Row-based (key column cycle membership) ───────────────────────────────

print("\n" + "="*70)
print("E: Row-based — tableau key column cycle membership")
print("="*70)
for hole_set, label in [(C17, "17cyc"), (C8, "8cyc")]:
    run_mask(f"E-{label}", mask_rowkey(hole_set))

# ── F: Cipher XOR Tableau → cycle membership ─────────────────────────────────

print("\n" + "="*70)
print("F: Cipher−Tableau diff → cycle membership")
print("="*70)
for hole_set, label in [(C17, "17cyc"), (C8, "8cyc"), (C17 | CZ, "17+Z")]:
    run_mask(f"F-diff-{label}", mask_diff_cipher_tableau(hole_set))

# ── C: Permutation power ──────────────────────────────────────────────────────

print("\n" + "="*70)
print("C: Permutation power (letters whose perm^n lands in cycle)")
print("="*70)
for n in [1, 2, 4, 8, 17, 68]:
    for thresh, thresh_label in [(C17, "17cyc"), (C8, "8cyc")]:
        run_mask(f"C-n{n}-{thresh_label}", mask_perm_power(n, thresh, 'cipher'),
                 verbose=False)

# Print only notable C results
print("  [C results with score > -380 or crib:]")
c_notable = [r for r in ALL_RESULTS if r['name'].startswith('C-') and (r['score'] > -380 or r['crib'])]
for r in sorted(c_notable, key=lambda x: x['score'], reverse=True)[:5]:
    print(f"  {r['name']}: k4={r['k4']}/97 score={r['score']:.1f} ({r['pc']:.2f}) "
          f"key={r['key']} {r['cipher']}/{r['alpha']} | {r['pt'][:40]}"
          + (" *** CRIB ***" if r['crib'] else ""))

# ── G: K3 verification ────────────────────────────────────────────────────────

print("\n" + "="*70)
print("G: K3 Verification — do holes in K3 region decrypt to Carter tomb text?")
print("="*70)

def k3_check(name, mask):
    h_text = ''.join(cg(r,c) for r,c in K3_POS if mask[r][c] and cg(r,c))
    s_text = ''.join(cg(r,c) for r,c in K3_POS if not mask[r][c] and cg(r,c))
    print(f"\n  {name}: holes={len(h_text)} solids={len(s_text)}")
    for text, tlabel in [(h_text, 'holes'), (s_text, 'solids')]:
        if len(text) < 10:
            continue
        for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
            for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
                pt = vig_decrypt(text, kw, alpha)
                sc_total = score_text(pt)
                sc_pc = sc_total / max(1, len(pt) - 3)
                # Check if K3_PT prefix appears
                found = K3_PT[:15] in pt
                if found or sc_pc > -5.0:
                    print(f"    {tlabel}/{kw}/{alpha_name}: pc={sc_pc:.2f} "
                          f"{'*** K3_PT MATCH ***' if found else ''} | {pt[:50]}")

for hole_set, label in [(C17, 'A-17cyc'), (C8, 'A-8cyc'),
                        (C17, 'D-17cyc'), (C8, 'D-8cyc')]:
    src = 'cipher' if label.startswith('A') else 'tableau'
    k3_check(label, mask_by_letter_set(hole_set, src))

# Also check: what if the K3 holes, re-ordered by the K3 transposition permutation,
# give the K3 real CT? (i.e., is the cycle mask CONSISTENT with K3's known scrambling?)
print("\n  [K3 transposition consistency check]")
def k3_perm_formula(i):
    """K3 CT[i] -> PT position (double rotational transposition)."""
    a = i // 24; b = i % 24
    intermediate = 14 * b + 13 - a
    c = intermediate // 8; d = intermediate % 8
    return 42 * d + 41 - c

# Build K3 carved CT array (336 chars)
K3_CT_ARR = list(K3_CT[:336])
# Build K3 real CT by applying K3 transposition (real_ct[perm(i)] = carved[i])
K3_REAL_CT = [''] * 336
for i in range(len(K3_CT_ARR)):
    if i < 336:
        pt_pos = k3_perm_formula(i)
        if 0 <= pt_pos < 336:
            K3_REAL_CT[pt_pos] = K3_CT_ARR[i]
K3_REAL_CT_STR = ''.join(K3_REAL_CT)
print(f"  K3 real CT (via transposition, first 30): {K3_REAL_CT_STR[:30]}")

# Verify: vig_decrypt(K3_REAL_CT, KRYPTOS, KA) should give K3_PT
k3_pt_check = vig_decrypt(K3_REAL_CT_STR, 'KRYPTOS', KA)
match = K3_PT[:20] in k3_pt_check
print(f"  K3 real CT Vig/KRYPTOS/KA match = {match} | {k3_pt_check[:40]}")
if not match:
    k3_pt_check2 = vig_decrypt(K3_REAL_CT_STR, 'KRYPTOS', AZ)
    match2 = K3_PT[:20] in k3_pt_check2
    print(f"  K3 real CT Vig/KRYPTOS/AZ match = {match2} | {k3_pt_check2[:40]}")

# ── 180° grille validity check ────────────────────────────────────────────────

print("\n" + "="*70)
print("180° ROTATION GRILLE VALIDITY ANALYSIS")
print("="*70)
print("For a valid 180° Cardan grille: each pair (r,c)+(27-r,30-c) needs exactly ONE hole.")
print("434/434 pairs = perfect validity.\n")
for hole_set, label, src in [
    (C17, "A-cipher-17cyc", 'cipher'),
    (C8,  "A-cipher-8cyc",  'cipher'),
    (C17, "D-tab-17cyc",    'tableau'),
    (C8,  "D-tab-8cyc",     'tableau'),
]:
    m = mask_by_letter_set(hole_set, src)
    rv = rot180_valid_pairs(m)
    total, k4h = mask_stats(m)
    print(f"  {label}: valid_pairs={rv}/434 ({rv/434*100:.1f}%) total={total}/868 k4={k4h}/97")

# ── Final Summary ─────────────────────────────────────────────────────────────

print("\n" + "="*70)
print("FINAL SUMMARY: TOP 25 RESULTS BY QUADGRAM SCORE")
print("="*70)
# English K4 (97 chars) would score ~-400 total, ~-4.26/quadgram
# Random K4 = ~-940 total
ALL_RESULTS.sort(key=lambda x: x['score'], reverse=True)

for r in ALL_RESULTS[:25]:
    crib_flag = " *** CRIB ***" if r['crib'] else ""
    print(f"  {r['name']:<40} k4={r['k4']:2d}/97 sc={r['score']:7.1f} pc={r['pc']:6.2f} "
          f"{r['key']}/{r['cipher']}/{r['alpha']} | {r['pt'][:35]}{crib_flag}")

# Crib summary
crib_hits = [r for r in ALL_RESULTS if r['crib']]
print(f"\n{'='*70}")
print(f"CRIB HITS: {len(crib_hits)}")
for r in crib_hits:
    print(f"  {r['name']}: {r['pt']}")

# English baseline for reference
print(f"\n[Score reference: 97-char English ~-400 total (-4.26/q), random ~-940 (-10/q)]")
print(f"[K4 raw (no scramble): score = {score_text(K4_CARVED):.1f} ({score_text_per_char(K4_CARVED):.2f}/q)]")
print(f"[Global best seen: {GLOBAL_BEST_SCORE:.1f}]")
