#!/usr/bin/env python3
"""
Cipher: multi-layer
Family: grille
Status: active
Keyspace: see implementation
Last run: 2026-03-05
Best score:

Test VERDIGRIS as a K4 keyword in every viable role:
1. Direct Vigenère/Beaufort/VarBeau (AZ + KA alphabets)
2. Autokey primer (all 6 variants)
3. Columnar transposition key
4. Combined: VERDIGRIS transposition + known keyword Vig/Beau
5. Combined: known keyword transposition + VERDIGRIS Vig/Beau
6. VERDIGRIS as Quagmire alphabet keyword
7. Double transposition with VERDIGRIS + another keyword
"""

import sys, os, json, math, itertools
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

AZ = ALPH
KA = KRYPTOS_ALPHABET
AZ_IDX = ALPH_IDX
KA_IDX = {c: i for i, c in enumerate(KA)}

# Load quadgrams
with open("data/english_quadgrams.json") as f:
    QG = json.load(f)
QG_FLOOR = min(QG.values()) - 1.0

def qscore(text):
    t = ''.join(c for c in text.upper() if c in AZ)
    if len(t) < 4: return -99.0
    return sum(QG.get(t[i:i+4], QG_FLOOR) for i in range(len(t)-3)) / (len(t)-3)

def has_cribs(text):
    hits = []
    if 'EASTNORTHEAST' in text: hits.append(('ENE', text.index('EASTNORTHEAST')))
    if 'BERLINCLOCK' in text: hits.append(('BC', text.index('BERLINCLOCK')))
    return hits

def check_self_enc(text):
    """Check self-encrypting positions."""
    if len(text) < 74: return []
    hits = []
    if text[32] == 'S': hits.append(32)
    if text[73] == 'K': hits.append(73)
    return hits

# Cipher primitives
def vig_d(ct, key, alph=AZ):
    idx = {c: i for i, c in enumerate(alph)}
    return ''.join(alph[(idx[c] - idx[key[i % len(key)]]) % 26] for i, c in enumerate(ct))

def beau_d(ct, key, alph=AZ):
    idx = {c: i for i, c in enumerate(alph)}
    return ''.join(alph[(idx[key[i % len(key)]] - idx[c]) % 26] for i, c in enumerate(ct))

def varbeau_d(ct, key, alph=AZ):
    idx = {c: i for i, c in enumerate(alph)}
    return ''.join(alph[(idx[c] + idx[key[i % len(key)]]) % 26] for i, c in enumerate(ct))

def autokey_vig_d_pt(ct, primer, alph=AZ):
    idx = {c: i for i, c in enumerate(alph)}
    key = list(primer)
    pt = []
    for i, c in enumerate(ct):
        k = key[i] if i < len(key) else pt[i - len(primer)]
        p = alph[(idx[c] - idx[k]) % 26]
        pt.append(p)
    return ''.join(pt)

def autokey_vig_d_ct(ct, primer, alph=AZ):
    idx = {c: i for i, c in enumerate(alph)}
    key = list(primer)
    pt = []
    for i, c in enumerate(ct):
        k = key[i] if i < len(key) else ct[i - len(primer)]
        p = alph[(idx[c] - idx[k]) % 26]
        pt.append(p)
    return ''.join(pt)

def autokey_beau_d_pt(ct, primer, alph=AZ):
    idx = {c: i for i, c in enumerate(alph)}
    key = list(primer)
    pt = []
    for i, c in enumerate(ct):
        k = key[i] if i < len(key) else pt[i - len(primer)]
        p = alph[(idx[k] - idx[c]) % 26]
        pt.append(p)
    return ''.join(pt)

def autokey_beau_d_ct(ct, primer, alph=AZ):
    idx = {c: i for i, c in enumerate(alph)}
    key = list(primer)
    pt = []
    for i, c in enumerate(ct):
        k = key[i] if i < len(key) else ct[i - len(primer)]
        p = alph[(idx[k] - idx[c]) % 26]
        pt.append(p)
    return ''.join(pt)

def autokey_varbeau_d_pt(ct, primer, alph=AZ):
    idx = {c: i for i, c in enumerate(alph)}
    key = list(primer)
    pt = []
    for i, c in enumerate(ct):
        k = key[i] if i < len(key) else pt[i - len(primer)]
        p = alph[(idx[c] + idx[k]) % 26]
        pt.append(p)
    return ''.join(pt)

def autokey_varbeau_d_ct(ct, primer, alph=AZ):
    idx = {c: i for i, c in enumerate(alph)}
    key = list(primer)
    pt = []
    for i, c in enumerate(ct):
        k = key[i] if i < len(key) else ct[i - len(primer)]
        p = alph[(idx[c] + idx[k]) % 26]
        pt.append(p)
    return ''.join(pt)

def columnar_decrypt(ct, key):
    """Columnar transposition decrypt with keyword."""
    ncols = len(key)
    nrows = math.ceil(len(ct) / ncols)
    total = nrows * ncols
    empty = total - len(ct)

    # Column order from key
    order = sorted(range(ncols), key=lambda i: key[i])

    # Distribute CT into columns
    cols = [''] * ncols
    pos = 0
    for col_idx in order:
        col_len = nrows - (1 if col_idx >= ncols - empty else 0)
        cols[col_idx] = ct[pos:pos+col_len]
        pos += col_len

    # Read row by row
    pt = []
    for r in range(nrows):
        for c in range(ncols):
            if r < len(cols[c]):
                pt.append(cols[c][r])
    return ''.join(pt[:len(ct)])

def keyword_to_perm(key):
    """Convert keyword to column permutation (alphabetical order, left-to-right tiebreak)."""
    return sorted(range(len(key)), key=lambda i: (key[i], i))

def keyword_mixed_alphabet(keyword, alph=AZ):
    """Generate a keyword-mixed alphabet."""
    seen = set()
    result = []
    for c in keyword.upper():
        if c not in seen and c in alph:
            seen.add(c)
            result.append(c)
    for c in alph:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return ''.join(result)


print("=" * 70)
print("VERDIGRIS KEYWORD EXPLORATION FOR K4")
print("=" * 70)

VERDIGRIS = "VERDIGRIS"
OTHER_KEYS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN"]
results = []  # (score, description, plaintext, self_enc, cribs)

def test(desc, pt):
    sc = qscore(pt)
    se = check_self_enc(pt)
    cr = has_cribs(pt)
    results.append((sc, desc, pt, se, cr))
    if cr:
        print(f"  *** CRIB HIT *** {desc}: {pt[:60]} score={sc:.3f}")
    if len(se) == 2:
        print(f"  *** SELF-ENC BOTH *** {desc}: {pt[:60]} score={sc:.3f}")
    return sc

# ── Phase 1: Direct single-layer ─────────────────────────────────────────
print("\n--- Phase 1: Direct Vigenère/Beaufort with VERDIGRIS ---")

for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
    for cipher_name, cipher_fn in [("Vig", vig_d), ("Beau", beau_d), ("VarBeau", varbeau_d)]:
        pt = cipher_fn(CT, VERDIGRIS, alph)
        desc = f"Direct {cipher_name}/{alph_name}/VERDIGRIS"
        sc = test(desc, pt)
        if sc > -5.5:
            print(f"  {desc}: {pt[:50]}... score={sc:.3f}")

# Also test reversed
for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
    for cipher_name, cipher_fn in [("Vig", vig_d), ("Beau", beau_d)]:
        pt = cipher_fn(CT[::-1], VERDIGRIS, alph)
        desc = f"Reversed {cipher_name}/{alph_name}/VERDIGRIS"
        test(desc, pt)

# ── Phase 2: Autokey with VERDIGRIS primer ────────────────────────────────
print("\n--- Phase 2: Autokey with VERDIGRIS primer ---")

autokey_fns = [
    ("Vig-PT", autokey_vig_d_pt), ("Vig-CT", autokey_vig_d_ct),
    ("Beau-PT", autokey_beau_d_pt), ("Beau-CT", autokey_beau_d_ct),
    ("VarBeau-PT", autokey_varbeau_d_pt), ("VarBeau-CT", autokey_varbeau_d_ct),
]

for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
    for ak_name, ak_fn in autokey_fns:
        pt = ak_fn(CT, VERDIGRIS, alph)
        desc = f"Autokey {ak_name}/{alph_name}/VERDIGRIS"
        sc = test(desc, pt)
        if sc > -5.5:
            print(f"  {desc}: {pt[:50]}... score={sc:.3f}")

# ── Phase 3: Columnar transposition with VERDIGRIS ────────────────────────
print("\n--- Phase 3: Columnar transposition with VERDIGRIS ---")

pt_col = columnar_decrypt(CT, VERDIGRIS)
desc = "Columnar/VERDIGRIS"
sc = test(desc, pt_col)
print(f"  {desc}: {pt_col[:50]}... score={sc:.3f}")

# Try reverse columnar (encrypt direction)
# For reverse: fill by columns in key order, read by rows
def columnar_encrypt_as_decrypt(ct, key):
    """Read CT by rows into grid, read by columns in key order."""
    ncols = len(key)
    nrows = math.ceil(len(ct) / ncols)
    order = sorted(range(ncols), key=lambda i: key[i])
    # Fill grid row by row
    grid = []
    for r in range(nrows):
        row = []
        for c in range(ncols):
            idx = r * ncols + c
            row.append(ct[idx] if idx < len(ct) else '')
        grid.append(row)
    # Read by columns in key order
    pt = []
    for c in order:
        for r in range(nrows):
            if grid[r][c]:
                pt.append(grid[r][c])
    return ''.join(pt)

pt_col_r = columnar_encrypt_as_decrypt(CT, VERDIGRIS)
desc = "Columnar-rev/VERDIGRIS"
sc = test(desc, pt_col_r)
print(f"  {desc}: {pt_col_r[:50]}... score={sc:.3f}")

# ── Phase 4: VERDIGRIS transposition + Vig/Beau with other key ────────────
print("\n--- Phase 4: Columnar(VERDIGRIS) then Vig/Beau(other key) ---")

for other in OTHER_KEYS:
    # Peel columnar first, then Vig/Beau
    ct_after_col = columnar_decrypt(CT, VERDIGRIS)
    for cipher_name, cipher_fn in [("Vig", vig_d), ("Beau", beau_d)]:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            pt = cipher_fn(ct_after_col, other, alph)
            desc = f"Col(VERDIGRIS)+{cipher_name}/{alph_name}/{other}"
            sc = test(desc, pt)
            if sc > -5.0:
                print(f"  INTERESTING: {desc}: {pt[:50]}... score={sc:.3f}")

# Reverse order: Vig/Beau first, then columnar
for other in OTHER_KEYS:
    for cipher_name, cipher_fn in [("Vig", vig_d), ("Beau", beau_d)]:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            ct_after_sub = cipher_fn(CT, other, alph)
            pt = columnar_decrypt(ct_after_sub, VERDIGRIS)
            desc = f"{cipher_name}/{alph_name}/{other}+Col(VERDIGRIS)"
            sc = test(desc, pt)
            if sc > -5.0:
                print(f"  INTERESTING: {desc}: {pt[:50]}... score={sc:.3f}")

# ── Phase 5: Other key transposition + VERDIGRIS Vig/Beau ────────────────
print("\n--- Phase 5: Columnar(other) then Vig/Beau(VERDIGRIS) ---")

for other in OTHER_KEYS:
    ct_after_col = columnar_decrypt(CT, other)
    for cipher_name, cipher_fn in [("Vig", vig_d), ("Beau", beau_d)]:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            pt = cipher_fn(ct_after_col, VERDIGRIS, alph)
            desc = f"Col({other})+{cipher_name}/{alph_name}/VERDIGRIS"
            sc = test(desc, pt)
            if sc > -5.0:
                print(f"  INTERESTING: {desc}: {pt[:50]}... score={sc:.3f}")

    # Reverse
    for cipher_name, cipher_fn in [("Vig", vig_d), ("Beau", beau_d)]:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            ct_after_sub = cipher_fn(CT, VERDIGRIS, alph)
            pt = columnar_decrypt(ct_after_sub, other)
            desc = f"{cipher_name}/{alph_name}/VERDIGRIS+Col({other})"
            sc = test(desc, pt)
            if sc > -5.0:
                print(f"  INTERESTING: {desc}: {pt[:50]}... score={sc:.3f}")

# ── Phase 6: Quagmire with VERDIGRIS alphabet ────────────────────────────
print("\n--- Phase 6: Quagmire (VERDIGRIS-keyed alphabet) ---")

verd_alph = keyword_mixed_alphabet(VERDIGRIS, AZ)
print(f"  VERDIGRIS-keyed alphabet: {verd_alph}")

# QIII: same keyed alphabet for both PT and CT, with various period keys
for period_key in OTHER_KEYS:
    # QIII-Vig: for each column, shift = keyed_alph.index(period_key_letter)
    vidx = {c: i for i, c in enumerate(verd_alph)}
    pt_chars = []
    for i, c in enumerate(CT):
        shift = vidx[period_key[i % len(period_key)]]
        pt_chars.append(verd_alph[(vidx[c] - shift) % 26])
    pt = ''.join(pt_chars)
    desc = f"QIII-Vig/VERDIGRIS-alph/{period_key}"
    sc = test(desc, pt)
    if sc > -5.0:
        print(f"  INTERESTING: {desc}: {pt[:50]}... score={sc:.3f}")

    # QIII-Beau
    pt_chars = []
    for i, c in enumerate(CT):
        shift = vidx[period_key[i % len(period_key)]]
        pt_chars.append(verd_alph[(shift - vidx[c]) % 26])
    pt = ''.join(pt_chars)
    desc = f"QIII-Beau/VERDIGRIS-alph/{period_key}"
    sc = test(desc, pt)
    if sc > -5.0:
        print(f"  INTERESTING: {desc}: {pt[:50]}... score={sc:.3f}")

# ── Phase 7: Double columnar (VERDIGRIS + other key) ─────────────────────
print("\n--- Phase 7: Double columnar transposition ---")

for other in OTHER_KEYS:
    # VERDIGRIS first, then other
    inter = columnar_decrypt(CT, VERDIGRIS)
    pt = columnar_decrypt(inter, other)
    desc = f"DblCol VERDIGRIS+{other}"
    sc = test(desc, pt)
    if sc > -5.0:
        print(f"  INTERESTING: {desc}: {pt[:50]}... score={sc:.3f}")

    # Other first, then VERDIGRIS
    inter = columnar_decrypt(CT, other)
    pt = columnar_decrypt(inter, VERDIGRIS)
    desc = f"DblCol {other}+VERDIGRIS"
    sc = test(desc, pt)
    if sc > -5.0:
        print(f"  INTERESTING: {desc}: {pt[:50]}... score={sc:.3f}")

# ── Phase 8: VERDIGRIS on scrambled CT (Model 2) ─────────────────────────
print("\n--- Phase 8: Model 2 — Columnar(VERDIGRIS) unscramble then Vig/Beau ---")
# Model: PT → Vig(key) → real_CT → Columnar(VERDIGRIS) → carved
# Decrypt: carved → Col_decrypt(VERDIGRIS) → real_CT → Vig_decrypt(key) → PT

unscrambled = columnar_decrypt(CT, VERDIGRIS)
print(f"  Unscrambled by Col(VERDIGRIS): {unscrambled[:50]}...")

for other in OTHER_KEYS:
    for cipher_name, cipher_fn in [("Vig", vig_d), ("Beau", beau_d)]:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            pt = cipher_fn(unscrambled, other, alph)
            desc = f"M2: Col(VERDIGRIS)→{cipher_name}/{alph_name}/{other}"
            sc = test(desc, pt)
            if sc > -5.0:
                print(f"  INTERESTING: {desc}: {pt[:50]}... score={sc:.3f}")

# Also reverse columnar direction
unscrambled_r = columnar_encrypt_as_decrypt(CT, VERDIGRIS)
for other in OTHER_KEYS:
    for cipher_name, cipher_fn in [("Vig", vig_d), ("Beau", beau_d)]:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            pt = cipher_fn(unscrambled_r, other, alph)
            desc = f"M2rev: Col(VERDIGRIS)→{cipher_name}/{alph_name}/{other}"
            sc = test(desc, pt)
            if sc > -5.0:
                print(f"  INTERESTING: {desc}: {pt[:50]}... score={sc:.3f}")

# ── Phase 9: VERDIGRIS as running key ─────────────────────────────────────
print("\n--- Phase 9: VERDIGRIS repeated as running key ---")
# Probably too short at 9 chars to be useful as running key, but test anyway
running = (VERDIGRIS * 11)[:CT_LEN]
for cipher_name, cipher_fn in [("Vig", vig_d), ("Beau", beau_d)]:
    pt = cipher_fn(CT, running)
    # This is identical to periodic Vig with period 9, already tested above
    # but let's also try VERDIGRIS concatenated with other keywords
    for other in OTHER_KEYS:
        combined_key = VERDIGRIS + other
        running2 = (combined_key * 10)[:CT_LEN]
        pt2 = vig_d(CT, running2)
        desc = f"Periodic Vig/{VERDIGRIS+other} (p={len(combined_key)})"
        sc = test(desc, pt2)
        if sc > -5.0:
            print(f"  INTERESTING: {desc}: {pt2[:50]}... score={sc:.3f}")

# ── Phase 10: Brute-force all column permutations for VERDIGRIS (9! = 362880) ──
print("\n--- Phase 10: All 9! column permutations for key length 9 ---")
# Instead of using VERDIGRIS alphabetical order, try ALL 362880 permutations
# of 9 columns, then apply Vig/Beau with top keywords

best_perm_score = -99
best_perm_result = None
n_perms = 0

for perm in itertools.permutations(range(9)):
    # Build a fake "key" that produces this permutation
    # We just need the column order, so directly do columnar with this perm
    ncols = 9
    nrows = math.ceil(CT_LEN / ncols)
    total = nrows * ncols
    empty = total - CT_LEN

    cols = [''] * ncols
    pos = 0
    for col_idx in perm:
        col_len = nrows - (1 if col_idx >= ncols - empty else 0)
        cols[col_idx] = CT[pos:pos+col_len]
        pos += col_len

    unscr = []
    for r in range(nrows):
        for c in range(ncols):
            if r < len(cols[c]):
                unscr.append(cols[c][r])
    unscr = ''.join(unscr[:CT_LEN])

    # Quick quadgram on raw unscrambled
    sc_raw = qscore(unscr)
    if sc_raw > best_perm_score:
        best_perm_score = sc_raw
        best_perm_result = (perm, "raw", unscr)

    # Try top 3 keywords with Vig/Beau AZ
    for key in ["KRYPTOS", "ABSCISSA", "PALIMPSEST"]:
        for fn, fn_name in [(vig_d, "Vig"), (beau_d, "Beau")]:
            pt = fn(unscr, key)
            sc = qscore(pt)
            if sc > best_perm_score:
                best_perm_score = sc
                best_perm_result = (perm, f"{fn_name}/AZ/{key}", pt)
            cr = has_cribs(pt)
            if cr:
                print(f"  *** CRIB HIT *** perm={perm} {fn_name}/{key}: {pt[:60]}")

    n_perms += 1
    if n_perms % 50000 == 0:
        print(f"  {n_perms:,}/362,880 perms, best={best_perm_score:.3f}")

print(f"\n  Best from 9! search: score={best_perm_score:.3f}")
if best_perm_result:
    perm, method, pt = best_perm_result
    print(f"  Perm: {perm}")
    print(f"  Method: {method}")
    print(f"  PT: {pt[:70]}")
    # Check if this perm matches VERDIGRIS ordering
    verd_perm = tuple(keyword_to_perm(VERDIGRIS))
    print(f"  VERDIGRIS perm: {verd_perm}")
    print(f"  Match: {perm == verd_perm}")

# ── Summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY — VERDIGRIS KEYWORD TESTS")
print("=" * 70)

# Sort by score
results.sort(key=lambda x: -x[0])

# Crib hits
crib_results = [r for r in results if r[4]]
if crib_results:
    print(f"\n*** CRIB HITS: {len(crib_results)} ***")
    for sc, desc, pt, se, cr in crib_results:
        print(f"  {sc:.3f} {desc}: {pt[:60]} cribs={cr}")
else:
    print("\nNo crib hits.")

# Self-encrypting
se_results = [r for r in results if len(r[3]) == 2]
if se_results:
    print(f"\n*** SELF-ENCRYPTING BOTH (pos 32=S, 73=K): {len(se_results)} ***")
    for sc, desc, pt, se, cr in se_results[:10]:
        print(f"  {sc:.3f} {desc}: {pt[:60]}")

# Top 20 by quadgram
print(f"\nTop 20 by quadgram score (total tested: {len(results)}):")
seen = set()
rank = 0
for sc, desc, pt, se, cr in results:
    sig = pt[:30]
    if sig in seen: continue
    seen.add(sig)
    rank += 1
    if rank > 20: break
    se_flag = " [SE]" if len(se) == 2 else ""
    cr_flag = " [CRIB!]" if cr else ""
    print(f"  {rank:2d}. [{sc:7.3f}] {desc}")
    print(f"      PT: {pt[:65]}{se_flag}{cr_flag}")

print(f"\nTotal configurations tested: {len(results)}")

# Save
os.makedirs("results", exist_ok=True)
with open("results/e_verdigris_keyword.json", "w") as f:
    top = [(sc, desc, pt[:97], se, cr) for sc, desc, pt, se, cr in results[:50]]
    json.dump({"keyword": "VERDIGRIS", "total_tested": len(results),
               "top_results": top}, f, indent=2, default=str)
