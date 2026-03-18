#!/usr/bin/env python3
"""
# Cipher: autokey_beaufort+vigenere
# Family: campaigns
# Status: active
# Keyspace: 5040 col7 orderings × 6 masks × 2 variants × 2 pipeline orders = 120,960
# Last run: never
# Best score: 0

Exhaustive col7 column-ordering search.

The 15/24 global high uses ASCENDING column order (0,1,2,3,4,5,6) for
the width-7 columnar transposition. Classical columnar trans uses
KEYWORD-ORDERED columns — and "KRYPTOS" has exactly 7 unique letters.

This script tests ALL 5,040 possible column reading orders for width-7
columnar transposition, combined with DEFECTOR:AZ_beau/vig autokey and
the 6 known 15/24 null masks, in both pipeline orderings:
  A: null_mask → inv_col7 → autokey_decrypt  (current model)
  B: null_mask → autokey_decrypt → inv_col7   (decrypt-first)
"""

import sys, time
from itertools import permutations

CT97 = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
N = 97
N_PT = 73
ENE_WORD = [ord(c) - 65 for c in 'EASTNORTHEAST']
BCL_WORD = [ord(c) - 65 for c in 'BERLINCLOCK']
ENE_START = 21
BCL_START = 63

SEEDS_15 = [
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95],
    [0,1,2,5,8,12,14,20,36,39,41,42,52,55,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,38,39,45,52,56,58,59,74,75,78,84,85,87,93,95],
    [0,1,2,5,8,12,14,20,36,41,42,44,52,55,58,59,74,75,78,84,85,88,93,96],
]

DEFECTOR = [ord(c) - 65 for c in 'DEFECTOR']
KRYPTOS_KW = [ord(c) - 65 for c in 'KRYPTOS']

# Thematic keywords to also try (in addition to DEFECTOR)
EXTRA_KEYWORDS = {
    'KRYPTOS': KRYPTOS_KW,
    'KOMPASS': [ord(c) - 65 for c in 'KOMPASS'],
    'ABSCISSA': [ord(c) - 65 for c in 'ABSCISSA'],
}


def columnar_perm_ordered(n, width, col_order):
    """Write row-by-row, read columns in col_order. Returns gather perm."""
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in col_order:
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm


def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def autokey_beau(ct, kw):
    """Beaufort autokey: P = (K - C) mod 26."""
    L = len(kw)
    pt = []
    for i, ci in enumerate(ct):
        ki = kw[i] if i < L else pt[i - L]
        pt.append((ki - ci) % 26)
    return pt


def autokey_vig(ct, kw):
    """Vigenère autokey: P = (C - K) mod 26."""
    L = len(kw)
    pt = []
    for i, ci in enumerate(ct):
        ki = kw[i] if i < L else pt[i - L]
        pt.append((ci - ki) % 26)
    return pt


def count_hits(pt, ene_s, bcl_s):
    e = sum(1 for j, c in enumerate(ENE_WORD) if ene_s + j < N_PT and pt[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD) if bcl_s + j < N_PT and pt[bcl_s + j] == c)
    return e + b, e, b


def keyword_col_order(word):
    """Column reading sequence from keyword (matches kernel convention).
    Returns the sequence of column indices to read, ordered by keyword rank."""
    indexed = sorted(range(len(word)), key=lambda i: word[i])
    # indexed[rank] = column_position, so reading sequence = indexed
    return indexed


def main():
    all_orders = list(permutations(range(7)))

    # Label some notable orderings
    labels = {}
    for name in ['KRYPTOS', 'ABCDEFG', 'GFEDCBA', 'MASKING', 'STEALTH',
                  'BERLINS', 'COMPASS', 'SHADOWS', 'CZARINA', 'COLUMNS',
                  'DEFECTO', 'PALIMPS', 'ENCRYPT', 'GRILLES']:
        if len(name) == 7:
            order = tuple(keyword_col_order([ord(c) - 65 for c in name]))
            labels[order] = name

    # All masks have same crib offsets (verified: n1=8, n2=16 for all)
    ene_s = ENE_START - 8   # = 13
    bcl_s = BCL_START - 16  # = 47

    # Pre-extract 73-char texts for each mask
    extracts = []
    for mask in SEEDS_15:
        null_set = frozenset(mask)
        ct73 = [ord(CT97[i]) - 65 for i in range(N) if i not in null_set]
        extracts.append(ct73)

    # Pre-compute all inverse permutations
    inv_perms = {}
    for order in all_orders:
        perm = columnar_perm_ordered(N_PT, 7, list(order))
        inv_perms[order] = reverse_perm(perm)

    print(f"Col7 keyword-ordered column search")
    print(f"Configs: {len(all_orders)} orderings × {len(SEEDS_15)} masks × 2 variants × 2 pipe_orders")
    print(f"Total: {len(all_orders) * len(SEEDS_15) * 4:,} evaluations")
    print(f"Baseline: ascending order (0,1,2,3,4,5,6) = 15/24 with DEFECTOR:AZ_beau")
    print(f"{'=' * 72}")
    sys.stdout.flush()

    t0 = time.time()
    best_overall = 0
    best_results = []
    total_evals = 0

    # Phase 1: DEFECTOR keyword, both variants, both pipeline orders
    for pipe_label, pipe_order in [('A:untrans→decrypt', 'A'), ('B:decrypt→untrans', 'B')]:
        for var_label, decrypt_fn in [('beau', autokey_beau), ('vig', autokey_vig)]:
            tag = f"DEFECTOR:AZ_{var_label} pipe={pipe_order}"

            for mi, ct73 in enumerate(extracts):
                for order in all_orders:
                    inv_p = inv_perms[order]
                    total_evals += 1

                    if pipe_order == 'A':
                        # A: untranspose first, then decrypt
                        ct_t = [ct73[inv_p[i]] for i in range(N_PT)]
                        pt = decrypt_fn(ct_t, DEFECTOR)
                    else:
                        # B: decrypt first, then untranspose
                        pt_scrambled = decrypt_fn(ct73, DEFECTOR)
                        pt = [pt_scrambled[inv_p[i]] for i in range(N_PT)]

                    total, e, b = count_hits(pt, ene_s, bcl_s)

                    if total > best_overall:
                        best_overall = total
                        pt_str = ''.join(chr(p + 65) for p in pt)
                        ol = labels.get(order, str(order))
                        best_results = [(total, e, b, mi, ol, tag, pt_str)]
                        print(f"\n*** NEW BEST: {total}/24 (e={e}/13, b={b}/11) mask={mi} order={ol} [{tag}]")
                        print(f"    PT: {pt_str}")
                        sys.stdout.flush()
                    elif total == best_overall and total >= 15:
                        pt_str = ''.join(chr(p + 65) for p in pt)
                        ol = labels.get(order, str(order))
                        best_results.append((total, e, b, mi, ol, tag, pt_str))
                        if len(best_results) <= 30:
                            print(f"    TIE: {total}/24 (e={e}/13, b={b}/11) mask={mi} order={ol} [{tag}]")
                            sys.stdout.flush()

    t1 = time.time()
    print(f"\n{'=' * 72}")
    print(f"Phase 1 done: {total_evals:,} evals in {t1 - t0:.1f}s")
    print(f"DEFECTOR best: {best_overall}/24 ({len(best_results)} configs)")

    # Phase 2: Extra keywords with ascending + KRYPTOS column orders
    print(f"\n{'=' * 72}")
    print(f"Phase 2: Extra keywords × notable column orderings")
    notable_orders = [
        ('ascending', tuple(range(7))),
        ('KRYPTOS', tuple(keyword_col_order(KRYPTOS_KW))),
        ('descending', (6, 5, 4, 3, 2, 1, 0)),
        ('interleaved', (0, 2, 4, 6, 1, 3, 5)),
    ]

    for kw_name, kw_nums in EXTRA_KEYWORDS.items():
        for ord_name, order in notable_orders:
            inv_p = inv_perms[order]
            for mi, ct73 in enumerate(extracts):
                for var_label, decrypt_fn in [('beau', autokey_beau), ('vig', autokey_vig)]:
                    total_evals += 1
                    ct_t = [ct73[inv_p[i]] for i in range(N_PT)]
                    pt = decrypt_fn(ct_t, kw_nums)
                    total, e, b = count_hits(pt, ene_s, bcl_s)
                    if total >= 13:
                        pt_str = ''.join(chr(p + 65) for p in pt)
                        tag = f"{kw_name}:AZ_{var_label} col7={ord_name}"
                        print(f"  {total}/24 (e={e}/13, b={b}/11) mask={mi} [{tag}]")
                        sys.stdout.flush()

    elapsed = time.time() - t0
    print(f"\n{'=' * 72}")
    print(f"TOTAL: {total_evals:,} evals in {elapsed:.1f}s")
    print(f"Global best: {best_overall}/24")

    if best_overall >= 15 and best_results:
        print(f"\nAll {best_overall}/24 results (first 30):")
        for total, e, b, mi, ol, tag, pt_str in best_results[:30]:
            print(f"  mask={mi} order={ol} [{tag}]")
            print(f"    PT: {pt_str}")

    if best_overall >= 16:
        print(f"\n!!! BREAKTHROUGH: {best_overall}/24 exceeds prior ceiling of 15/24 !!!")

    return 0 if best_overall <= 15 else 1


if __name__ == '__main__':
    sys.exit(main())
