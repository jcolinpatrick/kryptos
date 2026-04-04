#!/usr/bin/env python3 -u
"""
Cipher: Vatican matrix substitution
Family: substitution
Status: active
Keyspace: ~50 keywords x 10 fill orders x 3 variants x periods 1-20 = ~30K
Last run:
Best score:

CRYPTIANA VATICAN MATRIX: Column-Filled Keyword Matrix with Paired Equivalences

Hypothesis: A keyword fills a 5-column matrix column-by-column (not row-by-row).
This creates a non-standard mixed alphabet where certain letter pairs become
interchangeable (same row, equivalent columns). The resulting substitution
alphabet is then used for Beaufort/Vigenere polyalphabetic encryption.

From Cryptiana: Vatican ciphers used matrices where vowels headed columns,
consonants filled rows. The matrix structure created digit-pair equivalences
(1/2 interchangeable, 3/4 interchangeable). Applied to K4, the KRYPTOS
keyword filling a 5x6 matrix column-by-column creates a different alphabet
ordering than the standard row-by-row KA alphabet.

Two-system connection:
  System 1: Matrix-derived mixed alphabet (non-standard letter ordering)
  System 2: Polyalphabetic substitution using that alphabet
"""

import sys
import os
import json
import time
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ
from kryptos.kernel.alphabet import keyword_mixed_alphabet
from kryptos.kernel.scoring.aggregate import score_candidate

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRIB_POSITIONS = sorted(CRIB_DICT.keys())


def matrix_fill_column(keyword, n_cols=5):
    """Fill a matrix column-by-column with a keyword-deduped alphabet.

    Standard keyword_mixed_alphabet fills row-by-row:
      K R Y P T
      O S A B C
      D E F G H
      I J L M N
      Q U V W X
      Z

    Column-by-column fill:
      K O D I Q
      R S E J U
      Y A F L V
      P B G M W
      T C H N X
      Z

    Returns the alphabet read row-by-row from the column-filled matrix.
    """
    # Get deduped keyword alphabet (standard row-by-row)
    row_alpha = keyword_mixed_alphabet(keyword)

    n_letters = len(row_alpha)
    n_rows = (n_letters + n_cols - 1) // n_cols

    # Fill column by column
    matrix = [[None] * n_cols for _ in range(n_rows)]
    idx = 0
    for c in range(n_cols):
        for r in range(n_rows):
            if idx < n_letters:
                matrix[r][c] = row_alpha[idx]
                idx += 1

    # Read row by row
    result = ''
    for r in range(n_rows):
        for c in range(n_cols):
            if matrix[r][c] is not None:
                result += matrix[r][c]

    return result


def matrix_fill_diagonal(keyword, n_cols=5):
    """Fill matrix diagonally with keyword-deduped alphabet."""
    row_alpha = keyword_mixed_alphabet(keyword)
    n_letters = len(row_alpha)
    n_rows = (n_letters + n_cols - 1) // n_cols

    matrix = [[None] * n_cols for _ in range(n_rows)]
    idx = 0
    for diag in range(n_rows + n_cols - 1):
        for r in range(n_rows):
            c = diag - r
            if 0 <= c < n_cols and idx < n_letters:
                matrix[r][c] = row_alpha[idx]
                idx += 1

    result = ''
    for r in range(n_rows):
        for c in range(n_cols):
            if matrix[r][c] is not None:
                result += matrix[r][c]
    return result


def matrix_fill_spiral(keyword, n_cols=5):
    """Fill matrix in spiral order with keyword-deduped alphabet."""
    row_alpha = keyword_mixed_alphabet(keyword)
    n_letters = len(row_alpha)
    n_rows = (n_letters + n_cols - 1) // n_cols

    matrix = [[None] * n_cols for _ in range(n_rows)]

    # Generate spiral order positions
    positions = []
    top, bottom, left, right = 0, n_rows - 1, 0, n_cols - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            positions.append((top, c))
        top += 1
        for r in range(top, bottom + 1):
            positions.append((r, right))
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                positions.append((bottom, c))
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                positions.append((r, left))
            left += 1

    for idx, (r, c) in enumerate(positions):
        if idx < n_letters:
            matrix[r][c] = row_alpha[idx]

    result = ''
    for r in range(n_rows):
        for c in range(n_cols):
            if matrix[r][c] is not None:
                result += matrix[r][c]
    return result


def decrypt_with_alphabet(ct, key, ct_alphabet, variant='beau'):
    """Decrypt CT using a mixed alphabet for the CT row of the tableau."""
    ct_idx = {c: i for i, c in enumerate(ct_alphabet)}
    pt_idx = {c: i for i, c in enumerate(ALPHA)}  # PT uses standard alphabet

    result = []
    key_len = len(key)
    for i, c in enumerate(ct):
        k = key[i % key_len]
        ci = ct_idx.get(c)
        ki = pt_idx.get(k)
        if ci is None or ki is None:
            result.append('?')
            continue
        if variant == 'beau':
            pi = (ki - ci) % 26
        elif variant == 'vig':
            pi = (ci - ki) % 26
        else:  # vbeau
            pi = (ci + ki) % 26
        result.append(ALPHA[pi])
    return ''.join(result)


def test_config(args):
    """Test one (matrix_alphabet, keyword, period, variant) configuration."""
    label, ct_alphabet, keyword, variant = args

    pt = decrypt_with_alphabet(CT, keyword, ct_alphabet, variant)
    result = score_candidate(pt)

    if result.crib_score >= 10:
        return {
            "label": label,
            "keyword": keyword,
            "variant": variant,
            "ct_alphabet": ct_alphabet,
            "crib_score": result.crib_score,
            "bean_passed": result.bean_passed,
            "plaintext": pt[:40],
        }
    return None


def main():
    print("=" * 70)
    print("CRYPTIANA VATICAN MATRIX: Column-Filled Keyword Matrix")
    print("=" * 70)
    t0 = time.time()

    # Keywords to test
    keywords_matrix = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "EASTNORTHEAST",
        "DEFECTOR", "SHADOW", "ENIGMA", "SANBORN", "SCHEIDT",
        "KUBARK", "COMPASS", "CIPHER", "SECRET", "POINT",
        "ECLIPSE", "LUCID", "HELIED", "MATRIX", "QUARTZ",
        "LODESTONE", "SCULPTURE", "COPPER", "INVISIBLE",
        "BETWEEN", "SUBTLE", "SHADING", "ABSENCE", "LIGHT",
        "DIGETAL", "IQLUSION", "UNDERGRUUND", "DESPARATLY",
        "JUNCTION", "BUOY", "CHANNEL", "NAVIGATION",
        "ATBASH", "BEAUFORT", "VIGENERE", "TABLEAU",
    ]

    # Periodic keywords (for the polyalphabetic layer)
    periodic_keys = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SANBORN",
        "KUBARK", "POINT", "SEVEN", "BERLIN", "CLOCK",
        "SECRET", "CIPHER", "SHADOW", "ENIGMA", "LUCID",
        "K", "KR", "KRY", "KRYP", "KRYPT", "KRYPTO",
        "A", "AB", "ABC", "ABCD",
    ]

    fill_methods = [
        ("col", matrix_fill_column),
        ("diag", matrix_fill_diagonal),
        ("spiral", matrix_fill_spiral),
    ]

    # Also test standard row-fill (as control)
    fill_methods.append(("row", lambda kw, nc=5: keyword_mixed_alphabet(kw)))

    variants = ['beau', 'vig', 'vbeau']
    n_cols_options = [5, 6, 7]  # 5 = standard, 6 and 7 = wider matrices

    # Build work items
    work_items = []
    seen_alphabets = set()

    for matrix_kw in keywords_matrix:
        for fill_label, fill_fn in fill_methods:
            for n_cols in n_cols_options:
                try:
                    ct_alpha = fill_fn(matrix_kw, n_cols)
                except TypeError:
                    ct_alpha = fill_fn(matrix_kw)

                if len(ct_alpha) != 26:
                    continue
                if ct_alpha in seen_alphabets:
                    continue
                seen_alphabets.add(ct_alpha)

                for periodic_key in periodic_keys:
                    for variant in variants:
                        label = f"{matrix_kw}_{fill_label}_c{n_cols}_{periodic_key}_{variant}"
                        work_items.append((label, ct_alpha, periodic_key, variant))

    print(f"\n  {len(seen_alphabets)} unique matrix alphabets")
    print(f"  {len(work_items)} total configurations")

    # Scan
    print(f"\nScanning ({max(1, cpu_count()-2)} workers)...")
    n_workers = max(1, cpu_count() - 2)
    results = []

    with Pool(n_workers) as pool:
        for result in pool.imap_unordered(test_config, work_items, chunksize=200):
            if result is not None:
                results.append(result)

    elapsed = time.time() - t0
    results.sort(key=lambda r: -r['crib_score'])

    print(f"\n  Done in {elapsed:.1f}s")
    print(f"  {len(results)} configs scored >= 10")

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    if not results:
        print("\n  NO configs scored >= 10/24. All noise.")
    else:
        for r in results[:20]:
            bean = "PASS" if r['bean_passed'] else "FAIL"
            print(f"\n  {r['crib_score']}/24 [{bean}] {r['label']}")
            print(f"    CT alpha: {r['ct_alphabet']}")
            print(f"    PT: {r['plaintext']}...")

    # Save
    out = {
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "configs_tested": len(work_items),
        "unique_alphabets": len(seen_alphabets),
        "above_10": len(results),
        "runtime_s": round(elapsed, 1),
        "top_20": results[:20],
    }
    out_path = os.path.join(_ROOT, "results", "e_cryptiana_vatican_matrix_01.json")
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\n  Saved to {out_path}")
    print(f"  Total: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
