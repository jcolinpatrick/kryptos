#!/usr/bin/env python3
"""
Cipher: two_system
Family: archive_evidence
Status: active
Keyspace: ~1500 configs (atbash layer + sub + trans combinations)
Last run:
Best score:
"""
"""E-AAA-ATBASH-LAYER-02: Atbash as one layer of multi-layer system.

SOURCE: Archives of American Art, IMG_1340 mentions "ATBA[SH]" on same page as ABSCISSA.
Tests Atbash as a pre- or post-processing layer combined with Beaufort/Vigenere
and optional columnar transposition.

Also tests expanded keyword set including ECLIPSE, NORMANDY, thematic words from
the archive, and 3-keyword concatenations.
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


def atbash(text):
    return ''.join(AZ[25 - A2I[c]] for c in text)


def decrypt_beaufort(ct, key):
    klen = len(key)
    return ''.join(AZ[(A2I[key[i % klen]] - A2I[c]) % 26] for i, c in enumerate(ct))


def decrypt_vigenere(ct, key):
    klen = len(key)
    return ''.join(AZ[(A2I[c] - A2I[key[i % klen]]) % 26] for i, c in enumerate(ct))


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


# Archive-derived keywords + thematic extensions
KEYWORDS = [
    'ABSCISSA', 'ECLIPSE', 'NORMANDY', 'PALIMPSEST', 'KRYPTOS',
    'KUBARK', 'SHADOW', 'JUNCTION', 'COMPASS',
    # 3-keyword concatenations (from "3 words most" / "key words" plural)
    'KRYPTOSPALIMPSESTABSCISSA',
    'KRYPTOSABSCISSA',
    'PALIMPSESTABSCISSA',
    'ABSCISSAECLIPSE',
    'ECLIPSENORMANDY',
]

COL_WIDTHS = [4, 8, 10, 26]

best_score = 0
best_result = None
total = 0
hits = []

for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for keyword in KEYWORDS:
        for variant_name, decrypt_fn in [('beaufort', decrypt_beaufort), ('vigenere', decrypt_vigenere)]:
            # Test 1: Atbash(CT) → Beaufort(keyword)
            at_ct = atbash(ct_text)
            pt = decrypt_fn(at_ct, keyword)
            sc = score_candidate(pt) if ct_label == 'CT97' else score_candidate_free(pt)
            total += 1
            if sc.crib_score > best_score:
                best_score = sc.crib_score
                best_result = (ct_label, keyword, f'atbash_then_{variant_name}', 0, pt, sc)
            if sc.crib_score >= 10:
                hits.append((sc.crib_score, ct_label, keyword, f'atbash_then_{variant_name}', 0, pt[:40]))

            # Test 2: Beaufort(keyword) → Atbash
            pt2 = atbash(decrypt_fn(ct_text, keyword))
            sc2 = score_candidate(pt2) if ct_label == 'CT97' else score_candidate_free(pt2)
            total += 1
            if sc2.crib_score > best_score:
                best_score = sc2.crib_score
                best_result = (ct_label, keyword, f'{variant_name}_then_atbash', 0, pt2, sc2)
            if sc2.crib_score >= 10:
                hits.append((sc2.crib_score, ct_label, keyword, f'{variant_name}_then_atbash', 0, pt2[:40]))

            # Test 3: Atbash(CT) → Beaufort(keyword) → columnar(width)
            for width in COL_WIDTHS:
                pt3 = columnar_decipher(decrypt_fn(at_ct, keyword), width)
                sc3 = score_candidate(pt3) if ct_label == 'CT97' else score_candidate_free(pt3)
                total += 1
                if sc3.crib_score > best_score:
                    best_score = sc3.crib_score
                    best_result = (ct_label, keyword, f'atbash_{variant_name}_detrans', width, pt3, sc3)
                if sc3.crib_score >= 10:
                    hits.append((sc3.crib_score, ct_label, keyword, f'atbash_{variant_name}_detrans', width, pt3[:40]))

                # Test 4: columnar(width) → Atbash → Beaufort(keyword)
                dt = columnar_decipher(ct_text, width)
                pt4 = decrypt_fn(atbash(dt), keyword)
                sc4 = score_candidate(pt4) if ct_label == 'CT97' else score_candidate_free(pt4)
                total += 1
                if sc4.crib_score > best_score:
                    best_score = sc4.crib_score
                    best_result = (ct_label, keyword, f'detrans_atbash_{variant_name}', width, pt4, sc4)
                if sc4.crib_score >= 10:
                    hits.append((sc4.crib_score, ct_label, keyword, f'detrans_atbash_{variant_name}', width, pt4[:40]))

print(f"\n{'='*70}")
print(f"E-AAA-ATBASH-LAYER-02: Atbash + Beaufort/Vigenere + Columnar")
print(f"{'='*70}")
print(f"Configurations tested: {total}")
print(f"Best score: {best_score}")
if best_result:
    ct_label, kw, method, w, pt, sc = best_result
    print(f"  CT: {ct_label}, Keyword: {kw}")
    print(f"  Method: {method}, Width: {w}")
    print(f"  PT: {pt[:60]}...")
    print(f"  Score: {sc}")
if hits:
    print(f"\nHits (score >= 10):")
    for h in sorted(hits, reverse=True):
        print(f"  score={h[0]} {h[1]} kw={h[2]} method={h[3]} w={h[4]} pt={h[5]}")
else:
    print(f"\nNo hits >= 10")
print(f"{'='*70}")
