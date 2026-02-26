#!/usr/bin/env python3
"""Constrained permutation search for K4.

Sanborn said K4 is NOT mathematical. This script tests physically-motivated
constrained permutation structures:

1. STRIP TRANSPOSITIONS: Cut 97 chars into strips of length L, rearrange
   strips. For each strip ordering, try all 26 Vigenere key shifts per strip
   (or use SA to optimize key). Strip lengths: 7,8,9,11,13,14,24 and factors.

2. PHYSICAL FOLD/OVERLAY: Fold CT at various positions and combine halves
   using XOR, addition, subtraction mod 26. Also try reversing one half.

3. WELTZEITUHR (World Time Clock): 24 timezone sectors at Alexanderplatz.
   Use timezone orderings as permutation keys.

4. COLUMNAR TRANSPOSITION + SA KEY: Fix a columnar transposition width,
   enumerate column orderings, use SA to optimize Vigenere key.
"""

import json
import math
import os
import sys
import time
import itertools
import multiprocessing as mp
from pathlib import Path
from typing import List, Tuple, Optional

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, ALPH,
    BEAN_EQ, BEAN_INEQ, KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)

N = CT_LEN  # 97
CT_INT = np.array([ALPH_IDX[c] for c in CT], dtype=np.int8)
CRIB_POS = np.array(sorted(CRIB_DICT.keys()), dtype=np.int32)
CRIB_VAL = np.array([ALPH_IDX[CRIB_DICT[p]] for p in sorted(CRIB_DICT.keys())], dtype=np.int8)
BEAN_EQ_A = np.array([a for a, b in BEAN_EQ], dtype=np.int32)
BEAN_EQ_B = np.array([b for a, b in BEAN_EQ], dtype=np.int32)
BEAN_INEQ_A = np.array([a for a, b in BEAN_INEQ], dtype=np.int32)
BEAN_INEQ_B = np.array([b for a, b in BEAN_INEQ], dtype=np.int32)

# ── Quadgram LUT ─────────────────────────────────────────────────────────────
QUADGRAM_LUT = None


def load_quadgrams():
    global QUADGRAM_LUT
    qpath = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
    with open(qpath, 'r') as f:
        qdata = json.load(f)
    floor_val = min(qdata.values()) - 1.0
    QUADGRAM_LUT = np.full(26 ** 4, floor_val, dtype=np.float32)
    for qgram, logp in qdata.items():
        if len(qgram) == 4 and qgram.isalpha():
            idx = (ALPH_IDX[qgram[0]] * 17576 + ALPH_IDX[qgram[1]] * 676 +
                   ALPH_IDX[qgram[2]] * 26 + ALPH_IDX[qgram[3]])
            QUADGRAM_LUT[idx] = logp


def qg_score(pt_int: np.ndarray) -> float:
    p = pt_int.astype(np.int32)
    indices = p[:-3] * 17576 + p[1:-2] * 676 + p[2:-1] * 26 + p[3:]
    return float(np.sum(QUADGRAM_LUT[indices]))


def calc_ic(pt_int: np.ndarray) -> float:
    n = len(pt_int)
    if n < 2:
        return 0.0
    counts = np.bincount(pt_int, minlength=26)
    return float(np.sum(counts * (counts - 1))) / (n * (n - 1))


def crib_score(pt_int: np.ndarray) -> int:
    return int(np.sum(pt_int[CRIB_POS] == CRIB_VAL))


def bean_check(key: np.ndarray) -> bool:
    eq_ok = bool(np.all(key[BEAN_EQ_A] == key[BEAN_EQ_B]))
    ineq_ok = bool(np.all(key[BEAN_INEQ_A] != key[BEAN_INEQ_B]))
    return eq_ok and ineq_ok


def decrypt_vigenere(ct_int: np.ndarray, key: np.ndarray) -> np.ndarray:
    return (ct_int - key) % 26


def int_to_str(arr: np.ndarray) -> str:
    return ''.join(chr(c + 65) for c in arr)


# ══════════════════════════════════════════════════════════════════════════════
# 1. STRIP TRANSPOSITION
# ══════════════════════════════════════════════════════════════════════════════

def strip_permutation(ct_int: np.ndarray, strip_len: int, strip_order: list) -> np.ndarray:
    """Rearrange CT by cutting into strips and reordering.

    If 97 doesn't divide evenly, the last strip is shorter (padding model).
    strip_order[i] = j means the i-th position in output gets the j-th strip.
    """
    n = len(ct_int)
    num_full = n // strip_len
    remainder = n % strip_len
    num_strips = num_full + (1 if remainder > 0 else 0)

    # Extract strips
    strips = []
    for i in range(num_strips):
        start = i * strip_len
        end = min(start + strip_len, n)
        strips.append(ct_int[start:end])

    # Reorder
    result = []
    for idx in strip_order:
        if idx < len(strips):
            result.append(strips[idx])
    return np.concatenate(result)[:n]


def test_strip_transposition_exhaustive(strip_len: int) -> list:
    """Test all permutations of strips for a given strip length.

    For each strip ordering, try all 26 uniform shifts as a simple key,
    plus SA-optimized key for promising candidates.
    """
    if QUADGRAM_LUT is None:
        load_quadgrams()

    num_full = N // strip_len
    remainder = N % strip_len
    num_strips = num_full + (1 if remainder > 0 else 0)

    print(f"\n  Strip length {strip_len}: {num_strips} strips "
          f"({num_full} full + {'1 partial' if remainder else 'none partial'}), "
          f"{math.factorial(num_strips)} permutations", flush=True)

    if math.factorial(num_strips) > 50_000_000:
        print(f"    Too many permutations ({math.factorial(num_strips)}), skipping exhaustive", flush=True)
        return []

    results = []
    best_score = -1e9
    best_result = None
    tested = 0

    for perm in itertools.permutations(range(num_strips)):
        reordered = strip_permutation(CT_INT, strip_len, list(perm))

        # Try each of 26 uniform shifts
        for shift in range(26):
            key = np.full(N, shift, dtype=np.int8)
            pt_int = decrypt_vigenere(reordered, key)
            cs = crib_score(pt_int)

            if cs >= 6:  # Better than noise
                qg = qg_score(pt_int) / N
                bean_ok = bean_check(key)
                ic_val = calc_ic(pt_int)

                result = {
                    'strip_len': strip_len,
                    'perm': list(perm),
                    'shift': shift,
                    'crib': cs,
                    'bean_ok': bean_ok,
                    'qg_per_char': qg,
                    'ic': ic_val,
                    'plaintext': int_to_str(pt_int),
                }
                results.append(result)

                if cs > best_score or (cs == best_score and qg > best_result.get('qg_per_char', -99)):
                    best_score = cs
                    best_result = result
                    if cs >= 12:
                        print(f"    HIT: strip={strip_len} perm={list(perm)} shift={shift} "
                              f"crib={cs}/24 qg/c={qg:.3f} bean={'Y' if bean_ok else 'N'} "
                              f"PT={int_to_str(pt_int)[:50]}...", flush=True)

        tested += 1
        if tested % 10000 == 0:
            print(f"    ...{tested}/{math.factorial(num_strips)} perms tested, "
                  f"best crib={best_score}/24", flush=True)

    if best_result:
        print(f"    Best: crib={best_result['crib']}/24 qg/c={best_result['qg_per_char']:.3f} "
              f"perm={best_result['perm']} shift={best_result['shift']}", flush=True)
        print(f"    PT: {best_result['plaintext'][:70]}...", flush=True)

    return results


def test_strip_with_per_strip_key(strip_len: int) -> list:
    """For each strip permutation, optimize per-strip key (26^num_strips).

    Each strip gets its own uniform shift. This models a polyalphabetic
    cipher where each strip uses a different alphabet.
    """
    if QUADGRAM_LUT is None:
        load_quadgrams()

    num_full = N // strip_len
    remainder = N % strip_len
    num_strips = num_full + (1 if remainder > 0 else 0)

    # Only feasible for small numbers of strips with per-strip key
    total_perms = math.factorial(num_strips)
    total_keys = 26 ** num_strips

    print(f"\n  Strip len {strip_len}: {num_strips} strips, "
          f"{total_perms} perms x {total_keys} keys = {total_perms * total_keys} configs",
          flush=True)

    if total_perms * total_keys > 100_000_000:
        print(f"    Too many configs, using SA instead", flush=True)
        return test_strip_with_sa_key(strip_len)

    results = []
    best_score = -1e9
    best_result = None
    tested = 0

    for perm in itertools.permutations(range(num_strips)):
        reordered = strip_permutation(CT_INT, strip_len, list(perm))

        # Build key: each strip position gets its own shift
        for key_tuple in itertools.product(range(26), repeat=num_strips):
            key = np.zeros(N, dtype=np.int8)
            for strip_idx in range(num_strips):
                start = strip_idx * strip_len
                end = min(start + strip_len, N)
                key[start:end] = key_tuple[strip_idx]

            pt_int = decrypt_vigenere(reordered, key)
            cs = crib_score(pt_int)

            if cs >= 8:
                qg = qg_score(pt_int) / N
                bean_ok = bean_check(key)
                ic_val = calc_ic(pt_int)

                result = {
                    'strip_len': strip_len,
                    'perm': list(perm),
                    'strip_keys': list(key_tuple),
                    'crib': cs,
                    'bean_ok': bean_ok,
                    'qg_per_char': qg,
                    'ic': ic_val,
                    'plaintext': int_to_str(pt_int),
                }
                results.append(result)

                if cs > best_score:
                    best_score = cs
                    best_result = result
                    if cs >= 12:
                        print(f"    HIT: crib={cs}/24 qg/c={qg:.3f} "
                              f"perm={list(perm)} keys={list(key_tuple)}",
                              flush=True)

            tested += 1
            if tested % 5_000_000 == 0:
                print(f"    ...{tested/1e6:.1f}M configs, best crib={best_score}/24",
                      flush=True)

    if best_result:
        print(f"    Best: crib={best_result['crib']}/24 qg/c={best_result['qg_per_char']:.3f}",
              flush=True)
        print(f"    PT: {best_result['plaintext'][:70]}...", flush=True)

    return results


def test_strip_with_sa_key(strip_len: int) -> list:
    """For large strip counts, use SA to optimize both strip order and per-position key."""
    if QUADGRAM_LUT is None:
        load_quadgrams()

    num_full = N // strip_len
    remainder = N % strip_len
    num_strips = num_full + (1 if remainder > 0 else 0)

    print(f"  SA key search for strip_len={strip_len}, {num_strips} strips", flush=True)

    rng = np.random.RandomState(42)
    best_results = []

    for restart in range(200):
        # Random strip permutation and per-strip key
        perm = list(rng.permutation(num_strips))
        strip_keys = list(rng.randint(0, 26, size=num_strips))

        def build_key(sk):
            key = np.zeros(N, dtype=np.int8)
            for i in range(num_strips):
                s = i * strip_len
                e = min(s + strip_len, N)
                key[s:e] = sk[i]
            return key

        reordered = strip_permutation(CT_INT, strip_len, perm)
        key = build_key(strip_keys)
        pt_int = decrypt_vigenere(reordered, key)
        current_qg = qg_score(pt_int)

        temp = 5.0
        cooling = (0.001 / 5.0) ** (1.0 / 100000)

        for it in range(100000):
            r = rng.random()
            if r < 0.5 and num_strips > 1:
                # Swap two strips
                i, j = rng.randint(0, num_strips, size=2)
                while i == j:
                    j = rng.randint(0, num_strips)
                perm[i], perm[j] = perm[j], perm[i]
                reordered = strip_permutation(CT_INT, strip_len, perm)
                key = build_key(strip_keys)
                pt_int = decrypt_vigenere(reordered, key)
                new_qg = qg_score(pt_int)

                delta = new_qg - current_qg
                if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                    current_qg = new_qg
                else:
                    perm[i], perm[j] = perm[j], perm[i]
            else:
                # Change one strip key
                idx = rng.randint(0, num_strips)
                old = strip_keys[idx]
                strip_keys[idx] = int(rng.randint(0, 26))
                reordered = strip_permutation(CT_INT, strip_len, perm)
                key = build_key(strip_keys)
                pt_int = decrypt_vigenere(reordered, key)
                new_qg = qg_score(pt_int)

                delta = new_qg - current_qg
                if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                    current_qg = new_qg
                else:
                    strip_keys[idx] = old

            temp *= cooling

        # Evaluate final
        reordered = strip_permutation(CT_INT, strip_len, perm)
        key = build_key(strip_keys)
        pt_int = decrypt_vigenere(reordered, key)
        cs = crib_score(pt_int)
        qg = qg_score(pt_int) / N
        bean_ok = bean_check(key)
        ic_val = calc_ic(pt_int)

        if cs >= 6 or qg > -5.0:
            best_results.append({
                'strip_len': strip_len,
                'perm': perm[:],
                'strip_keys': strip_keys[:],
                'crib': cs,
                'bean_ok': bean_ok,
                'qg_per_char': qg,
                'ic': ic_val,
                'plaintext': int_to_str(pt_int),
            })

        if restart % 50 == 0:
            best_cs = max((r['crib'] for r in best_results), default=0)
            best_qg = max((r['qg_per_char'] for r in best_results), default=-99)
            print(f"    SA restart {restart}/200: best crib={best_cs}/24 qg/c={best_qg:.3f}",
                  flush=True)

    best_results.sort(key=lambda x: (-x['crib'], -x['qg_per_char']))
    if best_results:
        b = best_results[0]
        print(f"  SA best: crib={b['crib']}/24 qg/c={b['qg_per_char']:.3f} "
              f"bean={'Y' if b['bean_ok'] else 'N'}", flush=True)
        print(f"  PT: {b['plaintext'][:70]}...", flush=True)

    return best_results[:20]


# ══════════════════════════════════════════════════════════════════════════════
# 2. PHYSICAL FOLD / OVERLAY
# ══════════════════════════════════════════════════════════════════════════════

def test_fold_overlay() -> list:
    """Fold CT at various positions and combine halves.

    Try: XOR (addition mod 26), subtraction, with/without reversing one half.
    The fold position divides CT into left (0..fold-1) and right (fold..96).
    """
    if QUADGRAM_LUT is None:
        load_quadgrams()

    results = []
    print("\n  Testing fold/overlay at all positions...", flush=True)

    for fold_pos in range(20, 78):  # Reasonable fold positions
        left = CT_INT[:fold_pos]
        right = CT_INT[fold_pos:]
        len_left = len(left)
        len_right = len(right)
        min_len = min(len_left, len_right)

        # Pad shorter half with zeros for alignment
        operations = [
            ('add', lambda a, b: (a + b) % 26),
            ('sub_lr', lambda a, b: (a - b) % 26),
            ('sub_rl', lambda a, b: (b - a) % 26),
        ]

        for op_name, op_fn in operations:
            for reverse_right in [False, True]:
                r = right[::-1] if reverse_right else right

                # Align from left
                overlap = np.zeros(N, dtype=np.int8)
                for i in range(min_len):
                    overlap[i] = op_fn(left[i], r[i])
                # Remaining chars from the longer half
                if len_left > len_right:
                    overlap[min_len:len_left] = left[min_len:]
                    overlap_len = len_left
                else:
                    overlap[min_len:len_right] = r[min_len:]
                    overlap_len = len_right

                pt_int = overlap[:overlap_len]

                # Also try with each of 26 shifts on the result
                for shift in range(26):
                    shifted = (pt_int - shift) % 26
                    cs = crib_score_partial(shifted, overlap_len)
                    if cs >= 4:
                        qg = qg_score(shifted) / overlap_len if overlap_len > 3 else -99
                        result = {
                            'method': 'fold_overlay',
                            'fold_pos': fold_pos,
                            'operation': op_name,
                            'reverse_right': reverse_right,
                            'shift': shift,
                            'crib': cs,
                            'qg_per_char': qg,
                            'output_len': overlap_len,
                            'plaintext': int_to_str(shifted[:overlap_len]),
                        }
                        results.append(result)
                        if cs >= 8:
                            print(f"    HIT fold={fold_pos} op={op_name} "
                                  f"rev={'Y' if reverse_right else 'N'} shift={shift} "
                                  f"crib={cs}/24 qg/c={qg:.3f} "
                                  f"PT={int_to_str(shifted[:50])}...", flush=True)

    # Also test interleaving: take alternating chars from two halves
    print("\n  Testing interleave patterns...", flush=True)
    for fold_pos in [48, 49, 50]:
        left = CT_INT[:fold_pos]
        right = CT_INT[fold_pos:]

        for reverse_right in [False, True]:
            r = right[::-1] if reverse_right else right

            # Interleave: L[0] R[0] L[1] R[1] ...
            interleaved = np.zeros(N, dtype=np.int8)
            li, ri, oi = 0, 0, 0
            while oi < N:
                if li < len(left):
                    interleaved[oi] = left[li]
                    li += 1
                    oi += 1
                if oi < N and ri < len(r):
                    interleaved[oi] = r[ri]
                    ri += 1
                    oi += 1

            for shift in range(26):
                shifted = (interleaved - shift) % 26
                cs = crib_score(shifted)
                if cs >= 4:
                    qg = qg_score(shifted) / N
                    results.append({
                        'method': 'interleave',
                        'fold_pos': fold_pos,
                        'reverse_right': reverse_right,
                        'shift': shift,
                        'crib': cs,
                        'qg_per_char': qg,
                        'plaintext': int_to_str(shifted),
                    })
                    if cs >= 8:
                        print(f"    HIT interleave fold={fold_pos} "
                              f"rev={'Y' if reverse_right else 'N'} shift={shift} "
                              f"crib={cs}/24", flush=True)

    if results:
        results.sort(key=lambda x: (-x['crib'], -x['qg_per_char']))
        b = results[0]
        print(f"\n  Fold/overlay best: crib={b['crib']}/24 qg/c={b['qg_per_char']:.3f} "
              f"method={b['method']}", flush=True)
        print(f"  PT: {b['plaintext'][:70]}...", flush=True)
    else:
        print("  No fold/overlay results above threshold", flush=True)

    return results


def crib_score_partial(pt_int: np.ndarray, length: int) -> int:
    """Score cribs only for positions within the given length."""
    count = 0
    for i, pos in enumerate(CRIB_POS):
        if pos < length and pt_int[pos] == CRIB_VAL[i]:
            count += 1
    return count


# ══════════════════════════════════════════════════════════════════════════════
# 3. WELTZEITUHR (World Time Clock)
# ══════════════════════════════════════════════════════════════════════════════

def test_weltzeituhr() -> list:
    """Test transpositions based on Weltzeituhr timezone orderings.

    The Weltzeituhr at Alexanderplatz has 24 sectors for different timezones.
    Cities are arranged around the clock. We try using the timezone offset
    ordering as a columnar transposition key.
    """
    if QUADGRAM_LUT is None:
        load_quadgrams()

    # Weltzeituhr cities in their physical order around the clock (clockwise from top)
    # Each sector represents a timezone. The numbering/ordering is the key.
    # Standard UTC offsets from -12 to +12 (24 sectors, some half-hours omitted)
    # We'll try several plausible orderings.

    # Ordering 1: UTC offset order (the "natural" time order)
    utc_order = list(range(24))  # 0,1,2,...,23

    # Ordering 2: Alphabetical by major city
    # Major cities on the Weltzeituhr (approximate):
    weltzeituhr_cities = [
        "ACCRA", "ALGIERS", "ANKARA", "BAGHDAD", "BANGKOK",
        "BERLIN", "BUENOS_AIRES", "CAIRO", "CHICAGO", "DACCA",
        "DELHI", "HAVANA", "HONOLULU", "KABUL", "LONDON",
        "MEXICO", "MOSCOW", "NEW_YORK", "NOVOSIBIRSK", "PEKING",
        "PETROPAVLOVSK", "REYKJAVIK", "TOKYO", "VLADIVOSTOK",
    ]
    alpha_order = list(np.argsort([c for c in weltzeituhr_cities]))

    # Ordering 3: GMT offset of each city
    gmt_offsets = [
        0, 1, 2, 3, 7,    # Accra, Algiers, Ankara, Baghdad, Bangkok
        1, -3, 2, -6, 6,  # Berlin, Buenos Aires, Cairo, Chicago, Dacca
        5.5, -5, -10, 4.5, 0,  # Delhi, Havana, Honolulu, Kabul, London
        -6, 3, -5, 7, 8,  # Mexico, Moscow, NY, Novosibirsk, Peking
        12, 0, 9, 10,     # Petropavlovsk, Reykjavik, Tokyo, Vladivostok
    ]
    gmt_sort_order = list(np.argsort(gmt_offsets))

    orderings = {
        'utc_sequential': utc_order,
        'alphabetical': alpha_order,
        'gmt_sorted': gmt_sort_order,
        'reverse_utc': list(reversed(utc_order)),
        'reverse_alpha': list(reversed(alpha_order)),
    }

    # Also try KRYPTOS alphabet ordering mapped to 24 sectors
    kryptos_order = []
    for i, c in enumerate(KRYPTOS_ALPHABET[:24]):
        kryptos_order.append(ALPH_IDX[c] % 24)
    orderings['kryptos_alpha_mod24'] = kryptos_order

    results = []
    print("\n  Testing Weltzeituhr-based transpositions...", flush=True)

    # Use each ordering as a columnar transposition key with width 24
    # 97 chars in 24 columns: 4 full rows + 1 char remainder
    width = 24
    num_rows = (N + width - 1) // width  # 5 rows (last has 1 char)

    for name, order in orderings.items():
        # Write CT into grid row by row, read out column by column in the given order
        # Standard columnar transposition
        grid = np.full((num_rows, width), -1, dtype=np.int8)
        for i in range(N):
            row = i // width
            col = i % width
            grid[row, col] = CT_INT[i]

        # Read columns in the specified order
        reordered = []
        for col_idx in order:
            for row in range(num_rows):
                val = grid[row, col_idx]
                if val >= 0:
                    reordered.append(val)
        reordered = np.array(reordered[:N], dtype=np.int8)

        # Try all 26 shifts
        for shift in range(26):
            pt_int = (reordered - shift) % 26
            cs = crib_score(pt_int)
            if cs >= 4:
                qg = qg_score(pt_int) / N
                results.append({
                    'method': f'weltzeituhr_{name}',
                    'width': width,
                    'order': order[:],
                    'shift': shift,
                    'crib': cs,
                    'qg_per_char': qg,
                    'plaintext': int_to_str(pt_int),
                })
                if cs >= 8:
                    print(f"    HIT: {name} shift={shift} crib={cs}/24 "
                          f"qg/c={qg:.3f}", flush=True)

        # Also try inverse: write in column order, read row by row
        inv_grid = np.full((num_rows, width), -1, dtype=np.int8)
        pos = 0
        for col_idx in order:
            for row in range(num_rows):
                if row * width + col_idx < N:
                    inv_grid[row, col_idx] = CT_INT[pos]
                    pos += 1
                    if pos >= N:
                        break
            if pos >= N:
                break

        inv_reordered = []
        for row in range(num_rows):
            for col in range(width):
                if inv_grid[row, col] >= 0:
                    inv_reordered.append(inv_grid[row, col])
        inv_reordered = np.array(inv_reordered[:N], dtype=np.int8)

        for shift in range(26):
            pt_int = (inv_reordered - shift) % 26
            cs = crib_score(pt_int)
            if cs >= 4:
                qg = qg_score(pt_int) / N
                results.append({
                    'method': f'weltzeituhr_inv_{name}',
                    'width': width,
                    'order': order[:],
                    'shift': shift,
                    'crib': cs,
                    'qg_per_char': qg,
                    'plaintext': int_to_str(pt_int),
                })
                if cs >= 8:
                    print(f"    HIT inv: {name} shift={shift} crib={cs}/24 "
                          f"qg/c={qg:.3f}", flush=True)

    # Try widths other than 24 too
    for width in [4, 7, 8, 9, 11, 13, 14]:
        # Use the Weltzeituhr orderings truncated/wrapped to this width
        for name, order in orderings.items():
            col_order = [o % width for o in order[:width]]
            # Deduplicate
            seen = set()
            deduped = []
            for o in col_order:
                if o not in seen:
                    seen.add(o)
                    deduped.append(o)
            if len(deduped) != width:
                continue  # Can't form valid permutation

            num_rows_w = (N + width - 1) // width
            grid = np.full((num_rows_w, width), -1, dtype=np.int8)
            for i in range(N):
                grid[i // width, i % width] = CT_INT[i]

            reordered = []
            for col_idx in deduped:
                for row in range(num_rows_w):
                    val = grid[row, col_idx]
                    if val >= 0:
                        reordered.append(val)
            reordered = np.array(reordered[:N], dtype=np.int8)

            for shift in range(26):
                pt_int = (reordered - shift) % 26
                cs = crib_score(pt_int)
                if cs >= 4:
                    qg = qg_score(pt_int) / N
                    results.append({
                        'method': f'weltzeituhr_w{width}_{name}',
                        'width': width,
                        'order': deduped[:],
                        'shift': shift,
                        'crib': cs,
                        'qg_per_char': qg,
                        'plaintext': int_to_str(pt_int),
                    })

    if results:
        results.sort(key=lambda x: (-x['crib'], -x['qg_per_char']))
        b = results[0]
        print(f"\n  Weltzeituhr best: crib={b['crib']}/24 qg/c={b['qg_per_char']:.3f} "
              f"method={b['method']}", flush=True)
        print(f"  PT: {b['plaintext'][:70]}...", flush=True)
    else:
        print("  No Weltzeituhr results above threshold", flush=True)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 4. COLUMNAR TRANSPOSITION + SA KEY (structured permutations)
# ══════════════════════════════════════════════════════════════════════════════

def test_columnar_sa(width: int, n_restarts: int = 100) -> list:
    """Test columnar transposition at given width with SA-optimized key.

    For each column ordering (SA-optimized), find the best per-position
    Vigenere key using SA.
    """
    if QUADGRAM_LUT is None:
        load_quadgrams()

    num_rows = (N + width - 1) // width
    last_row_cols = N - (num_rows - 1) * width  # Columns with full length

    print(f"\n  Columnar SA: width={width}, {num_rows} rows, "
          f"{last_row_cols} full-length cols", flush=True)

    rng = np.random.RandomState(42)
    results = []

    def columnar_decrypt(col_order):
        """Decrypt columnar transposition: write cols in given order, read rows."""
        grid = np.full((num_rows, width), -1, dtype=np.int8)
        pos = 0
        for col_idx in col_order:
            col_len = num_rows if col_idx < last_row_cols else num_rows - 1
            for row in range(col_len):
                if pos < N:
                    grid[row, col_idx] = CT_INT[pos]
                    pos += 1
        # Read row by row
        result = []
        for row in range(num_rows):
            for col in range(width):
                if grid[row, col] >= 0:
                    result.append(grid[row, col])
        return np.array(result[:N], dtype=np.int8)

    for restart in range(n_restarts):
        col_order = list(rng.permutation(width))
        key = rng.randint(0, 26, size=N, dtype=np.int8)
        key[27] = key[65]  # Bean equality

        decrypted = columnar_decrypt(col_order)
        pt_int = decrypt_vigenere(decrypted, key)
        current_qg = qg_score(pt_int)

        best_qg_local = current_qg
        best_col_order = col_order[:]
        best_key = key.copy()

        temp = 5.0
        cooling = (0.001 / 5.0) ** (1.0 / 200000)

        for it in range(200000):
            r = rng.random()
            if r < 0.4:
                # Swap two columns
                i, j = rng.randint(0, width, size=2)
                while i == j:
                    j = rng.randint(0, width)
                col_order[i], col_order[j] = col_order[j], col_order[i]
                decrypted = columnar_decrypt(col_order)
                pt_int = decrypt_vigenere(decrypted, key)
                new_qg = qg_score(pt_int)

                if new_qg > current_qg or rng.random() < math.exp((new_qg - current_qg) / max(temp, 1e-10)):
                    current_qg = new_qg
                    if new_qg > best_qg_local:
                        best_qg_local = new_qg
                        best_col_order = col_order[:]
                        best_key = key.copy()
                else:
                    col_order[i], col_order[j] = col_order[j], col_order[i]
            else:
                # Change one key value
                pos = rng.randint(0, N)
                old_val = int(key[pos])
                new_val = int(rng.randint(0, 26))
                key[pos] = new_val
                if pos == 27:
                    key[65] = new_val
                elif pos == 65:
                    key[27] = new_val

                pt_int = decrypt_vigenere(decrypted, key)
                new_qg = qg_score(pt_int)

                if new_qg > current_qg or rng.random() < math.exp((new_qg - current_qg) / max(temp, 1e-10)):
                    current_qg = new_qg
                    if new_qg > best_qg_local:
                        best_qg_local = new_qg
                        best_col_order = col_order[:]
                        best_key = key.copy()
                else:
                    key[pos] = old_val
                    if pos == 27:
                        key[65] = old_val
                    elif pos == 65:
                        key[27] = old_val

            temp *= cooling

        # Evaluate best from this restart
        decrypted = columnar_decrypt(best_col_order)
        pt_int = decrypt_vigenere(decrypted, best_key)
        cs = crib_score(pt_int)
        qg = qg_score(pt_int) / N
        bean_ok = bean_check(best_key)
        ic_val = calc_ic(pt_int)

        results.append({
            'width': width,
            'col_order': best_col_order,
            'crib': cs,
            'bean_ok': bean_ok,
            'qg_per_char': qg,
            'ic': ic_val,
            'plaintext': int_to_str(pt_int),
        })

        if restart % 25 == 0:
            best_cs = max(r['crib'] for r in results)
            best_qg_all = max(r['qg_per_char'] for r in results)
            print(f"    Restart {restart}/{n_restarts}: best crib={best_cs}/24 "
                  f"qg/c={best_qg_all:.3f}", flush=True)

    results.sort(key=lambda x: (-x['crib'], -x['qg_per_char']))
    if results:
        b = results[0]
        print(f"  Columnar w={width} best: crib={b['crib']}/24 "
              f"qg/c={b['qg_per_char']:.3f} bean={'Y' if b['bean_ok'] else 'N'} "
              f"ic={b['ic']:.4f}", flush=True)
        print(f"  PT: {b['plaintext'][:70]}...", flush=True)

    return results[:10]


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 80, flush=True)
    print("K4 Constrained Permutation Search", flush=True)
    print(f"CT: {CT}", flush=True)
    print(f"Sanborn: 'NOT mathematical', 'other ways to make codes'", flush=True)
    print("=" * 80, flush=True)

    load_quadgrams()
    print(f"Quadgrams loaded ({len(QUADGRAM_LUT)} entries)", flush=True)

    results_dir = Path(__file__).parent.parent / 'results' / 'sa_assault'
    results_dir.mkdir(parents=True, exist_ok=True)

    all_results = {}
    start_time = time.time()

    # ── 1. Strip Transpositions ──────────────────────────────────────────
    print(f"\n{'='*60}", flush=True)
    print("STAGE 1: Strip Transpositions", flush=True)
    print(f"{'='*60}", flush=True)

    # 97 = prime, so no exact division. Test various strip lengths.
    # With strip_len L, we get ceil(97/L) strips.
    strip_results = {}

    # Small strip counts (exhaustive with uniform key)
    for strip_len in [24, 14, 13, 11, 9]:
        num_strips = (N + strip_len - 1) // strip_len
        if math.factorial(num_strips) <= 1_000_000:
            r = test_strip_transposition_exhaustive(strip_len)
            strip_results[strip_len] = r
            all_results[f'strip_L{strip_len}_uniform'] = r

    # Per-strip key (feasible for small strip counts)
    for strip_len in [24, 14]:
        num_strips = (N + strip_len - 1) // strip_len
        total = math.factorial(num_strips) * (26 ** num_strips)
        if total <= 100_000_000:
            r = test_strip_with_per_strip_key(strip_len)
            all_results[f'strip_L{strip_len}_per_strip_key'] = r

    # SA for larger counts
    for strip_len in [8, 7]:
        r = test_strip_with_sa_key(strip_len)
        all_results[f'strip_L{strip_len}_sa'] = r

    # ── 2. Physical Fold/Overlay ─────────────────────────────────────────
    print(f"\n{'='*60}", flush=True)
    print("STAGE 2: Physical Fold / Overlay", flush=True)
    print(f"{'='*60}", flush=True)

    fold_results = test_fold_overlay()
    all_results['fold_overlay'] = fold_results

    # ── 3. Weltzeituhr ───────────────────────────────────────────────────
    print(f"\n{'='*60}", flush=True)
    print("STAGE 3: Weltzeituhr (World Time Clock) Transpositions", flush=True)
    print(f"{'='*60}", flush=True)

    wtz_results = test_weltzeituhr()
    all_results['weltzeituhr'] = wtz_results

    # ── 4. Columnar + SA Key ─────────────────────────────────────────────
    print(f"\n{'='*60}", flush=True)
    print("STAGE 4: Columnar Transposition + SA Key", flush=True)
    print(f"{'='*60}", flush=True)

    for width in [7, 8, 9, 11, 13, 14]:
        r = test_columnar_sa(width, n_restarts=80)
        all_results[f'columnar_w{width}_sa'] = r

    # ── Final Summary ────────────────────────────────────────────────────
    total_elapsed = time.time() - start_time

    print(f"\n{'='*80}", flush=True)
    print("FINAL SUMMARY", flush=True)
    print(f"Elapsed: {total_elapsed:.0f}s ({total_elapsed/60:.1f}min)", flush=True)

    for method, results in all_results.items():
        if not results:
            continue
        best = max(results, key=lambda x: x.get('crib', 0))
        print(f"\n  {method}: {len(results)} candidates, "
              f"best crib={best.get('crib', 0)}/24 "
              f"qg/c={best.get('qg_per_char', -99):.3f}", flush=True)
        if best.get('crib', 0) >= 8:
            print(f"    PT: {best.get('plaintext', '?')[:70]}...", flush=True)

    # Save results (convert numpy types for JSON)
    def sanitize(obj):
        if isinstance(obj, (np.integer,)):
            return int(obj)
        if isinstance(obj, (np.floating,)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, dict):
            return {k: sanitize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [sanitize(v) for v in obj]
        return obj

    outpath = results_dir / 'constrained_results.json'
    with open(outpath, 'w') as f:
        json.dump(sanitize({
            'experiment': 'constrained_permutations',
            'elapsed_seconds': total_elapsed,
            'results': {k: v[:10] for k, v in all_results.items()},  # Top 10 each
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        }), f, indent=2)
    print(f"\nResults saved to {outpath}", flush=True)
    print("Done.", flush=True)


if __name__ == '__main__':
    main()
