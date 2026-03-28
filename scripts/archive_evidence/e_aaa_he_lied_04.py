#!/usr/bin/env python3
"""
Cipher: two_system
Family: archive_evidence
Status: active
Keyspace: ~800 configs
Last run:
Best score:
"""
"""E-AAA-HE-LIED-04: Tests derived from the "He lied" coordinate note.

SOURCE: IMG_1389 — Sanborn wrote two coordinate sets with "He lied" circled:
  Original: 38°57'6.5" N, 77°8'44" W (K2 decoded coordinates, near CIA)
  Changed:  37°57'6.5" N, 77°8'44" W (one degree south)

Tests:
  1. HELIED as a Beaufort/Vigenere keyword (period 6)
  2. Coordinate digits as Gronsfeld-style numeric keys
  3. Width/period = 37 or derived from coordinates
  4. HELIED as a crib (search for it in Beaufort/Vig decryptions)
  5. Combinations with other archive keywords
"""
import sys, os
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CONSENSUS_NULL_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

CT97 = CT
CT73 = ''.join(c for i, c in enumerate(CT97) if i not in CONSENSUS_NULL_POSITIONS)

AZ = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
A2I = {c: i for i, c in enumerate(AZ)}


def decrypt_beaufort(ct, key):
    klen = len(key)
    return ''.join(AZ[(A2I[key[i % klen]] - A2I[c]) % 26] for i, c in enumerate(ct))


def decrypt_vigenere(ct, key):
    klen = len(key)
    return ''.join(AZ[(A2I[c] - A2I[key[i % klen]]) % 26] for i, c in enumerate(ct))


def gronsfeld_decrypt(ct, digits):
    """Gronsfeld: like Vigenere but key is numeric digits (shifts 0-9)."""
    klen = len(digits)
    return ''.join(AZ[(A2I[c] - digits[i % klen]) % 26] for i, c in enumerate(ct))


def gronsfeld_beaufort(ct, digits):
    """Beaufort with numeric key."""
    klen = len(digits)
    return ''.join(AZ[(digits[i % klen] - A2I[c]) % 26] for i, c in enumerate(ct))


def columnar_decipher(ct, width):
    n = len(ct)
    nrows = (n + width - 1) // width
    full_cols = n % width or width
    grid = [''] * width
    pos = 0
    for col in range(width):
        col_len = nrows if col < full_cols else nrows - 1
        grid[col] = ct[pos:pos + col_len]
        pos += col_len
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(grid[col]):
                result.append(grid[col][row])
    return ''.join(result)


best_score = 0
best_result = None
total = 0
hits = []


def test(pt, ct_label, desc):
    global best_score, best_result, total
    sc = score_candidate(pt) if ct_label == 'CT97' else score_candidate_free(pt)
    total += 1
    if sc.crib_score > best_score:
        best_score = sc.crib_score
        best_result = (ct_label, desc, pt, sc)
    if sc.crib_score >= 10:
        hits.append((sc.crib_score, ct_label, desc, pt[:40]))
    # Also check if HELIED appears as plaintext fragment
    if 'HELIED' in pt or 'THELIED' in pt or 'HELIED' in pt:
        print(f"  *** HELIED found in plaintext! {desc} -> {pt[:60]}")


for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:

    # === Test 1: HELIED as keyword ===
    for var_name, fn in [('beau', decrypt_beaufort), ('vig', decrypt_vigenere)]:
        pt = fn(ct_text, 'HELIED')
        test(pt, ct_label, f'HELIED_{var_name}')

        # With columnar
        for w in [4, 6, 8, 10, 26, 37]:
            pt2 = columnar_decipher(fn(ct_text, 'HELIED'), w)
            test(pt2, ct_label, f'HELIED_{var_name}_col{w}')
            pt3 = fn(columnar_decipher(ct_text, w), 'HELIED')
            test(pt3, ct_label, f'col{w}_HELIED_{var_name}')

    # === Test 2: Coordinate digits as Gronsfeld key ===
    digit_keys = {
        'orig_38': [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],
        'mod_37':  [3, 7, 5, 7, 6, 5, 7, 7, 8, 4, 4],
        'lat_orig': [3, 8, 5, 7, 6, 5],
        'lat_mod':  [3, 7, 5, 7, 6, 5],
        'lon': [7, 7, 8, 4, 4],
        'all_combined': [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4, 3, 7, 5, 7, 6, 5, 7, 7, 8, 4, 4],
        'diff_only': [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # the lie itself
        'short_38_77': [3, 8, 7, 7],
        'short_37_77': [3, 7, 7, 7],
    }

    for dname, digits in digit_keys.items():
        pt = gronsfeld_decrypt(ct_text, digits)
        test(pt, ct_label, f'grons_{dname}')
        pt2 = gronsfeld_beaufort(ct_text, digits)
        test(pt2, ct_label, f'grons_beau_{dname}')

        # With columnar
        for w in [4, 8, 10]:
            pt3 = columnar_decipher(gronsfeld_decrypt(ct_text, digits), w)
            test(pt3, ct_label, f'grons_{dname}_col{w}')
            pt4 = gronsfeld_decrypt(columnar_decipher(ct_text, w), digits)
            test(pt4, ct_label, f'col{w}_grons_{dname}')

    # === Test 3: Width/period = 37 ===
    for var_name, fn in [('beau', decrypt_beaufort), ('vig', decrypt_vigenere)]:
        for kw in ['ABSCISSA', 'ECLIPSE', 'NORMANDY', 'KRYPTOS', 'PALIMPSEST', 'HELIED']:
            pt = fn(columnar_decipher(ct_text, 37), kw)
            test(pt, ct_label, f'col37_{kw}_{var_name}')
            pt2 = columnar_decipher(fn(ct_text, kw), 37)
            test(pt2, ct_label, f'{kw}_{var_name}_col37')

    # === Test 4: HELIED combined with other archive keywords ===
    for kw2 in ['ABSCISSA', 'ECLIPSE', 'NORMANDY', 'PALIMPSEST', 'KRYPTOS']:
        # Double substitution: Beaufort(HELIED) then Beaufort(kw2)
        for fn in [decrypt_beaufort, decrypt_vigenere]:
            pt = fn(decrypt_beaufort(ct_text, 'HELIED'), kw2)
            test(pt, ct_label, f'HELIED_beau_then_{kw2}_{fn.__name__}')
            pt2 = fn(decrypt_beaufort(ct_text, kw2), 'HELIED')
            test(pt2, ct_label, f'{kw2}_beau_then_HELIED_{fn.__name__}')


print(f"\n{'='*70}")
print(f"E-AAA-HE-LIED-04: 'He lied' coordinate tests")
print(f"{'='*70}")
print(f"Configurations tested: {total}")
print(f"Best score: {best_score}")
if best_result:
    ct_label, desc, pt, sc = best_result
    print(f"  CT: {ct_label}")
    print(f"  Method: {desc}")
    print(f"  PT: {pt[:60]}...")
    print(f"  Score: {sc}")
if hits:
    print(f"\nHits (score >= 10):")
    for h in sorted(hits, reverse=True):
        print(f"  score={h[0]} {h[1]} method={h[2]} pt={h[3]}")
else:
    print(f"\nNo hits >= 10")
print(f"{'='*70}")
