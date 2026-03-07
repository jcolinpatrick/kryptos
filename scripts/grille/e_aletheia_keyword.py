#!/usr/bin/env python3
"""
ALETHEIA keyword exploration for K4.

ALETHEIA (ἀλήθεια) = Greek for "truth" / "unconcealment" (Heidegger).
8 letters, period 8 = ABSCISSA length = Bean-compatible period.
Thematically perfect: the hidden truth revealed.

Tests: direct Vig/Beau/VBeau (AZ+KA), autokey (6 variants × 2 alphabets),
columnar transposition (8! = 40,320 perms), multi-layer combos with
known keywords, Model 2 unscramble-then-decrypt.

Cipher: Multiple
Family: grille
Status: active
"""
import sys, os, json
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    QG = json.load(f)
QG_FLOOR = min(QG.values()) - 1.0

def qg_score(text):
    if len(text) < 4:
        return QG_FLOOR
    return sum(QG.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3)) / (len(text) - 3)

def vig_decrypt(ct, key, alph=ALPH, idx=ALPH_IDX):
    kl = len(key)
    return ''.join(alph[(idx[c] - idx[key[i % kl]]) % 26] for i, c in enumerate(ct))

def beau_decrypt(ct, key, alph=ALPH, idx=ALPH_IDX):
    kl = len(key)
    return ''.join(alph[(idx[key[i % kl]] - idx[c]) % 26] for i, c in enumerate(ct))

def varbeau_decrypt(ct, key, alph=ALPH, idx=ALPH_IDX):
    kl = len(key)
    return ''.join(alph[(idx[c] + idx[key[i % kl]]) % 26] for i, c in enumerate(ct))

KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
KA_IDX = {c: i for i, c in enumerate(KA)}

def crib_score(pt):
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(pt) and pt[pos] == ch)

def free_crib_search(pt):
    total = 0
    details = []
    for crib in ('EASTNORTHEAST', 'BERLINCLOCK'):
        idx = pt.find(crib)
        if idx >= 0:
            total += len(crib)
            details.append((crib, idx))
    return total, details

def bean_check(pt, ct_text):
    ks = [(ALPH_IDX[c] - ALPH_IDX[p]) % 26 for c, p in zip(ct_text, pt)]
    for a, b in BEAN_EQ:
        if ks[a] != ks[b]:
            return False
    for a, b in BEAN_INEQ:
        if ks[a] == ks[b]:
            return False
    return True

def columnar_decrypt(ct, perm):
    ncols = len(perm)
    nrows = len(ct) // ncols
    extra = len(ct) % ncols
    # Build column lengths
    col_lens = [nrows + (1 if i < extra else 0) for i in range(ncols)]
    # Read columns in perm order
    cols = []
    pos = 0
    # Sort perm to get reading order
    order = sorted(range(ncols), key=lambda i: perm[i])
    col_data = [''] * ncols
    for col_idx in order:
        cl = col_lens[col_idx]
        col_data[col_idx] = ct[pos:pos+cl]
        pos += cl
    # Read row by row
    result = []
    for row in range(nrows + 1):
        for col in range(ncols):
            if row < len(col_data[col]):
                result.append(col_data[col][row])
    return ''.join(result)

COMPANION_KEYS = {
    'KRYPTOS': 'KRYPTOS',
    'PALIMPSEST': 'PALIMPSEST',
    'ABSCISSA': 'ABSCISSA',
    'SHADOW': 'SHADOW',
    'SANBORN': 'SANBORN',
    'VERDIGRIS': 'VERDIGRIS',
    'BERLIN': 'BERLIN',
    'URANIA': 'URANIA',
}

print("=" * 70)
print("ALETHEIA KEYWORD EXPLORATION FOR K4")
print("  ALETHEIA = Greek 'truth/unconcealment', 8 letters (period 8)")
print("=" * 70)

# ── Phase 1: Direct substitution ─────────────────────────────────────────────
print("\n--- Phase 1: Direct Vig/Beau/VBeau with ALETHEIA ---")
for alph_name, alph, idx in [('AZ', ALPH, ALPH_IDX), ('KA', KA, KA_IDX)]:
    for dname, dfunc in [('Vig', vig_decrypt), ('Beau', beau_decrypt), ('VBeau', varbeau_decrypt)]:
        pt = dfunc(CT, 'ALETHEIA', alph, idx)
        cs = crib_score(pt)
        qs = qg_score(pt)
        fc, fd = free_crib_search(pt)
        print(f"  {dname}/{alph_name}/ALETHEIA: crib={cs:2d}/24 qg={qs:.3f} free={fd} PT={pt[:60]}")

# ── Phase 2: Autokey ─────────────────────────────────────────────────────────
print("\n--- Phase 2: Autokey with ALETHEIA primer ---")
for alph_name, alph, idx in [('AZ', ALPH, ALPH_IDX), ('KA', KA, KA_IDX)]:
    for mode in ['Vig-PT', 'Vig-CT', 'Beau-PT', 'Beau-CT', 'VBeau-PT', 'VBeau-CT']:
        primer = 'ALETHEIA'
        pt_chars = []
        key_stream = list(primer)
        for i, c in enumerate(CT):
            if i < len(primer):
                k = primer[i]
            else:
                if 'CT' in mode:
                    k = CT[i - len(primer)]
                else:
                    k = pt_chars[i - len(primer)]
            if 'Vig' in mode:
                p = alph[(idx[c] - idx[k]) % 26]
            elif 'Beau' in mode:
                p = alph[(idx[k] - idx[c]) % 26]
            else:
                p = alph[(idx[c] + idx[k]) % 26]
            pt_chars.append(p)
        pt = ''.join(pt_chars)
        cs = crib_score(pt)
        qs = qg_score(pt)
        fc, fd = free_crib_search(pt)
        if cs >= 2 or qs > -6.5 or fc > 0:
            print(f"  Autokey {mode}/{alph_name}: crib={cs:2d} qg={qs:.3f} free={fd}")

# ── Phase 3: Columnar transposition with ALETHEIA (8! = 40,320) ─────────────
print("\n--- Phase 3: Columnar transposition (8! = 40,320 perms) ---")
# ALETHEIA letter order: A=0,L=1,E=2,T=3,H=4,E=5,I=6,A=7
# With ties broken left-to-right: A(0)=0, A(7)=1, E(2)=2, E(5)=3, H(4)=4, I(6)=5, L(1)=6, T(3)=7
ALETHEIA_PERM = [0, 6, 2, 7, 4, 3, 5, 1]  # column read order from keyword

phase3_best = (-999, '', '', None)
phase3_count = 0

for perm in permutations(range(8)):
    ct_dec = columnar_decrypt(CT, perm)
    phase3_count += 1

    # Try with Vig/Beau + companion keys
    for kname, key in [('ALETHEIA', 'ALETHEIA')] + list(COMPANION_KEYS.items()):
        for dname, dfunc in [('Vig', vig_decrypt), ('Beau', beau_decrypt)]:
            pt = dfunc(ct_dec, key)
            cs = crib_score(pt)
            fc, fd = free_crib_search(pt)
            if cs > phase3_best[0] or fc > 0:
                qs = qg_score(pt)
                phase3_best = (cs, pt, f"Col(perm)+{dname}/{kname}", perm)
                if cs >= 5 or fc > 0:
                    print(f"  ** crib={cs} free={fd} {dname}/{kname} perm={perm}")

    # Also try plain columnar (no substitution layer)
    cs_plain = crib_score(ct_dec)
    fc_plain, fd_plain = free_crib_search(ct_dec)
    if cs_plain > phase3_best[0] or fc_plain > 0:
        qs = qg_score(ct_dec)
        phase3_best = (cs_plain, ct_dec, f"Col(perm) plain", perm)
        if cs_plain >= 5 or fc_plain > 0:
            print(f"  ** PLAIN crib={cs_plain} free={fd_plain} perm={perm}")

    if phase3_count % 10000 == 0:
        print(f"  {phase3_count:,}/40,320 perms, best crib={phase3_best[0]}")

print(f"  Phase 3 complete: {phase3_count:,} perms, best crib={phase3_best[0]}")
if phase3_best[0] > 0:
    print(f"  Best: {phase3_best[2]} perm={phase3_best[3]}")
    print(f"  PT: {phase3_best[1][:70]}")

# ── Phase 4: Multi-layer: Col(companion) then Vig/Beau(ALETHEIA) ────────────
print("\n--- Phase 4: Col(companion key) then Vig/Beau(ALETHEIA) ---")
phase4_best = (-999, '', '')

for comp_name, comp_key in COMPANION_KEYS.items():
    comp_len = len(comp_key)
    if comp_len > 12:
        continue
    # Get keyword columnar perm
    indexed = sorted(range(comp_len), key=lambda i: (comp_key[i], i))
    comp_perm = [0] * comp_len
    for rank, orig in enumerate(indexed):
        comp_perm[orig] = rank

    ct_dec = columnar_decrypt(CT, comp_perm)
    for dname, dfunc in [('Vig', vig_decrypt), ('Beau', beau_decrypt), ('VBeau', varbeau_decrypt)]:
        for alph_name, alph, idx in [('AZ', ALPH, ALPH_IDX), ('KA', KA, KA_IDX)]:
            pt = dfunc(ct_dec, 'ALETHEIA', alph, idx)
            cs = crib_score(pt)
            fc, fd = free_crib_search(pt)
            qs = qg_score(pt)
            if cs > phase4_best[0]:
                phase4_best = (cs, pt, f"Col({comp_name})+{dname}/{alph_name}/ALETHEIA")
            if cs >= 4 or fc > 0:
                print(f"  crib={cs} free={fd} qg={qs:.3f} Col({comp_name})+{dname}/{alph_name}/ALETHEIA")

print(f"  Phase 4 best: crib={phase4_best[0]} via {phase4_best[2]}")

# ── Phase 5: Multi-layer: Vig/Beau(ALETHEIA) then Col(companion) ────────────
print("\n--- Phase 5: Vig/Beau(ALETHEIA) then Col(companion key) ---")
phase5_best = (-999, '', '')

for dname, dfunc in [('Vig', vig_decrypt), ('Beau', beau_decrypt), ('VBeau', varbeau_decrypt)]:
    for alph_name, alph, idx in [('AZ', ALPH, ALPH_IDX), ('KA', KA, KA_IDX)]:
        intermediate = dfunc(CT, 'ALETHEIA', alph, idx)
        for comp_name, comp_key in COMPANION_KEYS.items():
            comp_len = len(comp_key)
            if comp_len > 12:
                continue
            indexed = sorted(range(comp_len), key=lambda i: (comp_key[i], i))
            comp_perm = [0] * comp_len
            for rank, orig in enumerate(indexed):
                comp_perm[orig] = rank
            pt = columnar_decrypt(intermediate, comp_perm)
            cs = crib_score(pt)
            fc, fd = free_crib_search(pt)
            qs = qg_score(pt)
            if cs > phase5_best[0]:
                phase5_best = (cs, pt, f"{dname}/{alph_name}/ALETHEIA+Col({comp_name})")
            if cs >= 4 or fc > 0:
                print(f"  crib={cs} free={fd} qg={qs:.3f} {dname}/{alph_name}/ALETHEIA+Col({comp_name})")

print(f"  Phase 5 best: crib={phase5_best[0]} via {phase5_best[2]}")

# ── Phase 6: Model 2 — Col(ALETHEIA) unscramble then Vig/Beau ───────────────
print("\n--- Phase 6: Model 2 — Col(ALETHEIA) unscramble then decrypt ---")
phase6_best = (-999, '', '')

# Try all 8! columnar permutations as unscrambling
for perm in permutations(range(8)):
    unscrambled = columnar_decrypt(CT, perm)
    for kname, key in [('KRYPTOS', 'KRYPTOS'), ('ABSCISSA', 'ABSCISSA'),
                        ('PALIMPSEST', 'PALIMPSEST'), ('ALETHEIA', 'ALETHEIA')]:
        for dname, dfunc in [('Vig', vig_decrypt), ('Beau', beau_decrypt)]:
            pt = dfunc(unscrambled, key)
            fc, fd = free_crib_search(pt)
            if fc > 0:
                cs = crib_score(pt)
                qs = qg_score(pt)
                print(f"  *** FREE CRIB: {fd} crib={cs} qg={qs:.3f}")
                print(f"      Unscramble perm={perm} then {dname}/{kname}")
                print(f"      PT: {pt}")

            # Also check anchored cribs on the unscrambled text
            cs = crib_score(pt)
            if cs > phase6_best[0]:
                phase6_best = (cs, pt, f"M2: Col(perm={perm})+{dname}/{kname}")

print(f"  Phase 6 best: crib={phase6_best[0]}")

# ── Phase 7: ALETHEIA as Quagmire alphabet keyword ──────────────────────────
print("\n--- Phase 7: Quagmire with ALETHEIA-keyed alphabet ---")
def keyword_alphabet(kw):
    seen = set()
    result = []
    for ch in kw + ALPH:
        if ch not in seen:
            seen.add(ch)
            result.append(ch)
    return ''.join(result)

aletheia_alph = keyword_alphabet('ALETHEIA')
aletheia_idx = {c: i for i, c in enumerate(aletheia_alph)}
print(f"  ALETHEIA-keyed alphabet: {aletheia_alph}")

for comp_name, comp_key in list(COMPANION_KEYS.items()) + [('ALETHEIA', 'ALETHEIA')]:
    for mode in ['QIII-Vig', 'QIII-Beau']:
        # QIII: same keyed alphabet for PT and CT, keyword as shift source
        pt_chars = []
        kl = len(comp_key)
        for i, c in enumerate(CT):
            k = comp_key[i % kl]
            shift = aletheia_idx[k]
            if 'Vig' in mode:
                p = aletheia_alph[(aletheia_idx[c] - shift) % 26]
            else:
                p = aletheia_alph[(shift - aletheia_idx[c]) % 26]
            pt_chars.append(p)
        pt = ''.join(pt_chars)
        cs = crib_score(pt)
        qs = qg_score(pt)
        fc, fd = free_crib_search(pt)
        if cs >= 2 or qs > -6.5:
            print(f"  {mode}/{comp_name}: crib={cs} qg={qs:.3f} free={fd}")

# ── Phase 8: ALETHEIA + KRYPTOS double keyword ──────────────────────────────
print("\n--- Phase 8: Double keyword (ALETHEIA period 8 + KRYPTOS period 7) ---")
# Combined period = LCM(8,7) = 56. Effective key = 56 chars.
for mode1 in ['Vig', 'Beau']:
    for mode2 in ['Vig', 'Beau']:
        pt_chars = []
        for i, c in enumerate(CT):
            k1 = 'ALETHEIA'[i % 8]
            k2 = 'KRYPTOS'[i % 7]
            val = ALPH_IDX[c]
            if mode1 == 'Vig':
                val = (val - ALPH_IDX[k1]) % 26
            else:
                val = (ALPH_IDX[k1] - val) % 26
            if mode2 == 'Vig':
                val = (val - ALPH_IDX[k2]) % 26
            else:
                val = (ALPH_IDX[k2] - val) % 26
            pt_chars.append(ALPH[val])
        pt = ''.join(pt_chars)
        cs = crib_score(pt)
        qs = qg_score(pt)
        fc, fd = free_crib_search(pt)
        print(f"  {mode1}(ALETHEIA)+{mode2}(KRYPTOS): crib={cs} qg={qs:.3f} free={fd} PT={pt[:50]}")

# Same with ABSCISSA (also period 8 — same period, different key)
print("\n  Double keyword ALETHEIA+ABSCISSA (both period 8, combined still 8):")
for mode1 in ['Vig', 'Beau']:
    for mode2 in ['Vig', 'Beau']:
        pt_chars = []
        for i, c in enumerate(CT):
            k1 = 'ALETHEIA'[i % 8]
            k2 = 'ABSCISSA'[i % 8]
            val = ALPH_IDX[c]
            if mode1 == 'Vig':
                val = (val - ALPH_IDX[k1]) % 26
            else:
                val = (ALPH_IDX[k1] - val) % 26
            if mode2 == 'Vig':
                val = (val - ALPH_IDX[k2]) % 26
            else:
                val = (ALPH_IDX[k2] - val) % 26
            pt_chars.append(ALPH[val])
        pt = ''.join(pt_chars)
        cs = crib_score(pt)
        qs = qg_score(pt)
        fc, fd = free_crib_search(pt)
        print(f"  {mode1}(ALETHEIA)+{mode2}(ABSCISSA): crib={cs} qg={qs:.3f} free={fd} PT={pt[:50]}")

# ── Summary ──────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY — ALETHEIA KEYWORD TESTS")
print("=" * 70)

all_bests = [
    ('Phase 3 (Col 8!)', phase3_best[0]),
    ('Phase 4 (Col+Vig)', phase4_best[0]),
    ('Phase 5 (Vig+Col)', phase5_best[0]),
    ('Phase 6 (Model 2)', phase6_best[0]),
]
for name, score in all_bests:
    print(f"  {name}: best crib = {score}")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)
