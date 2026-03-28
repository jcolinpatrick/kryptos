#!/usr/bin/env python3
"""
Cipher: two_system
Family: archive_evidence
Status: active
Keyspace: 4 keywords x 4 widths x 2 peel orders x 3 variants x 2 CT forms = 192 configs
Last run:
Best score:
"""
"""E-AAA-BEAUFORT-TRANS-01: Archive-evidenced Beaufort + columnar transposition.

SOURCE: Archives of American Art, Jim Sanborn papers (2026-03-27).
  - IMG_1569: Beaufort cipher listed in Sanborn's handwritten cipher types
  - IMG_1340: "4, 8, 10, 26 = Col" — possible column widths
  - IMG_1340: "★ Definition of ABSCISSA" — keyword candidate
  - IMG_1566: "Eclipse" — keyword candidate
  - IMG_1569: "Normandy" — keyword candidate (underlined)
  - IMG_1617: "key words" (plural) used to decode
  - IMG_1555: Physical overlay "Code Breaker" concept

ATTACK: Beaufort/Vigenere/Variant-Beaufort with archive-derived keywords,
combined with columnar transposition at archive-derived widths.
Tests both peel orders (sub-then-trans, trans-then-sub) on both CT97 and CT73.
"""
import sys, os
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

import itertools
from kryptos.kernel.constants import CT, CONSENSUS_NULL_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

# --- Archive-derived parameters ---
KEYWORDS = ['ABSCISSA', 'ECLIPSE', 'NORMANDY', 'PALIMPSEST']
COL_WIDTHS = [4, 8, 10, 26]
VARIANTS = ['beaufort', 'vigenere', 'variant_beaufort']

# Extract CT73 (null-removed)
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


def decrypt_variant_beaufort(ct, key):
    klen = len(key)
    return ''.join(AZ[(A2I[c] + A2I[key[i % klen]]) % 26] for i, c in enumerate(ct))


DECRYPT = {
    'beaufort': decrypt_beaufort,
    'vigenere': decrypt_vigenere,
    'variant_beaufort': decrypt_variant_beaufort,
}


def columnar_decipher(ct, width):
    """Undo columnar transposition: text was written into rows of `width`,
    then columns read off in order. To decipher, fill columns back."""
    n = len(ct)
    nrows = (n + width - 1) // width
    full_cols = n % width or width  # number of columns with nrows chars

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


def columnar_encipher(pt, width):
    """Apply columnar transposition: write into rows, read off columns."""
    n = len(pt)
    nrows = (n + width - 1) // width
    result = []
    for col in range(width):
        for row in range(nrows):
            idx = row * width + col
            if idx < n:
                result.append(pt[idx])
    return ''.join(result)


def score_text(pt, ct_label):
    """Score using appropriate method."""
    if ct_label == 'CT97':
        return score_candidate(pt)
    else:
        return score_candidate_free(pt)


def run_attack():
    best_score = 0
    best_result = None
    total = 0
    hits = []

    for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
        for keyword in KEYWORDS:
            for variant in VARIANTS:
                decrypt_fn = DECRYPT[variant]
                for width in COL_WIDTHS:
                    # Peel order 1: substitution first, then undo transposition
                    # (cipher applied: transpose then substitute, so we undo sub then undo trans)
                    sub_first = decrypt_fn(ct_text, keyword)
                    pt1 = columnar_decipher(sub_first, width)
                    s1 = score_text(pt1, ct_label)

                    total += 1
                    if s1.crib_score > best_score:
                        best_score = s1.crib_score
                        best_result = (ct_label, keyword, variant, width, 'sub_then_detrans', pt1, s1)
                    if s1.crib_score >= 10:
                        hits.append((s1.crib_score, ct_label, keyword, variant, width, 'sub_then_detrans', pt1[:40]))

                    # Peel order 2: undo transposition first, then substitution
                    # (cipher applied: substitute then transpose, so we undo trans then undo sub)
                    detrans_first = columnar_decipher(ct_text, width)
                    pt2 = decrypt_fn(detrans_first, keyword)
                    s2 = score_text(pt2, ct_label)

                    total += 1
                    if s2.crib_score > best_score:
                        best_score = s2.crib_score
                        best_result = (ct_label, keyword, variant, width, 'detrans_then_sub', pt2, s2)
                    if s2.crib_score >= 10:
                        hits.append((s2.crib_score, ct_label, keyword, variant, width, 'detrans_then_sub', pt2[:40]))

    print(f"\n{'='*70}")
    print(f"E-AAA-BEAUFORT-TRANS-01: Beaufort + Columnar (Archive Evidence)")
    print(f"{'='*70}")
    print(f"Configurations tested: {total}")
    print(f"Keywords: {KEYWORDS}")
    print(f"Widths: {COL_WIDTHS}")
    print(f"Variants: {VARIANTS}")
    print(f"CT forms: CT97 ({len(CT97)} chars), CT73 ({len(CT73)} chars)")
    print(f"\nBest score: {best_score}")

    if best_result:
        ct_label, kw, var, w, order, pt, sc = best_result
        print(f"  CT: {ct_label}")
        print(f"  Keyword: {kw}")
        print(f"  Variant: {var}")
        print(f"  Width: {w}")
        print(f"  Peel order: {order}")
        print(f"  PT: {pt[:60]}...")
        print(f"  Score breakdown: {sc}")

    if hits:
        print(f"\nHits (score >= 10):")
        for h in sorted(hits, reverse=True):
            print(f"  score={h[0]} {h[1]} kw={h[2]} var={h[3]} w={h[4]} order={h[5]} pt={h[6]}")
    else:
        print(f"\nNo hits >= 10 (noise threshold)")

    print(f"\n{'='*70}")
    return best_score, total


if __name__ == '__main__':
    run_attack()
