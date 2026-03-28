#!/usr/bin/env python3
"""
Cipher: two_system
Family: archive_evidence
Status: active
Keyspace: ~2000 configs
Last run:
Best score:
"""
"""E-AAA-KEYED-COLUMNAR-03: Keyword-ordered columnar + substitution.

Unlike script 01 (simple columnar by width), this uses the KEYWORD ITSELF
to determine column reading order. E.g., ABSCISSA → alphabetical order
of letters gives column permutation [1,2,5,3,4,7,6,8] (for ABCISSSA sorted).

Also tests: Beaufort with one keyword, columnar keyed by ANOTHER keyword
(the "3 words" model where different keywords control different layers).
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


def keyword_to_col_order(keyword):
    """Convert keyword to column reading order via alphabetical sorting."""
    indexed = sorted(enumerate(keyword), key=lambda x: (x[1], x[0]))
    order = [0] * len(keyword)
    for rank, (orig_idx, _) in enumerate(indexed):
        order[orig_idx] = rank
    return order


def keyed_columnar_decipher(ct, keyword):
    """Decipher keyed columnar transposition."""
    width = len(keyword)
    n = len(ct)
    nrows = (n + width - 1) // width
    col_order = keyword_to_col_order(keyword)

    # Calculate column lengths
    remainder = n % width
    col_lengths = []
    for col in range(width):
        if remainder == 0:
            col_lengths.append(nrows)
        else:
            # Columns whose rank < remainder get an extra char
            col_lengths.append(nrows if col_order[col] < remainder else nrows - 1)

    # Fill columns in sorted order
    sorted_cols = sorted(range(width), key=lambda c: col_order[c])
    columns = [''] * width
    pos = 0
    for col in sorted_cols:
        clen = col_lengths[col]
        columns[col] = ct[pos:pos + clen]
        pos += clen

    # Read off rows
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(columns[col]):
                result.append(columns[col][row])
    return ''.join(result)


def keyed_columnar_encipher(pt, keyword):
    """Encipher with keyed columnar transposition."""
    width = len(keyword)
    n = len(pt)
    nrows = (n + width - 1) // width
    col_order = keyword_to_col_order(keyword)

    # Write into rows
    grid = []
    for row in range(nrows):
        row_chars = []
        for col in range(width):
            idx = row * width + col
            if idx < n:
                row_chars.append(pt[idx])
            else:
                row_chars.append('')
        grid.append(row_chars)

    # Read columns in key order
    sorted_cols = sorted(range(width), key=lambda c: col_order[c])
    result = []
    for col in sorted_cols:
        for row in range(nrows):
            if grid[row][col]:
                result.append(grid[row][col])
    return ''.join(result)


# Archive-derived keywords
SUB_KEYWORDS = ['ABSCISSA', 'ECLIPSE', 'NORMANDY', 'PALIMPSEST', 'KRYPTOS',
                'KUBARK', 'SHADOW', 'COMPASS']
TRANS_KEYWORDS = ['ABSCISSA', 'ECLIPSE', 'NORMANDY', 'PALIMPSEST', 'KRYPTOS',
                  'KUBARK', 'SHADOW', 'COMPASS']

best_score = 0
best_result = None
total = 0
hits = []

for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for sub_kw in SUB_KEYWORDS:
        for trans_kw in TRANS_KEYWORDS:
            for var_name, decrypt_fn in [('beaufort', decrypt_beaufort), ('vigenere', decrypt_vigenere)]:
                # Order 1: keyed columnar decipher → then substitution decrypt
                dt = keyed_columnar_decipher(ct_text, trans_kw)
                pt1 = decrypt_fn(dt, sub_kw)
                sc1 = score_candidate(pt1) if ct_label == 'CT97' else score_candidate_free(pt1)
                total += 1
                if sc1.crib_score > best_score:
                    best_score = sc1.crib_score
                    best_result = (ct_label, sub_kw, var_name, trans_kw, 'detrans_sub', pt1, sc1)
                if sc1.crib_score >= 10:
                    hits.append((sc1.crib_score, ct_label, sub_kw, var_name, trans_kw, 'detrans_sub', pt1[:40]))

                # Order 2: substitution decrypt → then keyed columnar decipher
                sub = decrypt_fn(ct_text, sub_kw)
                pt2 = keyed_columnar_decipher(sub, trans_kw)
                sc2 = score_candidate(pt2) if ct_label == 'CT97' else score_candidate_free(pt2)
                total += 1
                if sc2.crib_score > best_score:
                    best_score = sc2.crib_score
                    best_result = (ct_label, sub_kw, var_name, trans_kw, 'sub_detrans', pt2, sc2)
                if sc2.crib_score >= 10:
                    hits.append((sc2.crib_score, ct_label, sub_kw, var_name, trans_kw, 'sub_detrans', pt2[:40]))

print(f"\n{'='*70}")
print(f"E-AAA-KEYED-COLUMNAR-03: Keyword-ordered columnar + substitution")
print(f"{'='*70}")
print(f"Configurations tested: {total}")
print(f"Best score: {best_score}")
if best_result:
    ct_label, sub_kw, var_name, trans_kw, order, pt, sc = best_result
    print(f"  CT: {ct_label}")
    print(f"  Sub keyword: {sub_kw} ({var_name})")
    print(f"  Trans keyword: {trans_kw}")
    print(f"  Peel order: {order}")
    print(f"  PT: {pt[:60]}...")
    print(f"  Score: {sc}")
if hits:
    print(f"\nHits (score >= 10):")
    for h in sorted(hits, reverse=True):
        print(f"  score={h[0]} {h[1]} sub={h[2]} var={h[3]} trans={h[4]} order={h[5]} pt={h[6]}")
else:
    print(f"\nNo hits >= 10")
print(f"{'='*70}")
