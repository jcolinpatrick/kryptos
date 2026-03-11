#!/usr/bin/env python3
# Cipher: product (double columnar × substitution)
# Family: two_system
# Status: active
# Keyspace: K2 coordinate-derived column orders × periodic sub
# Last run:
# Best score:
#
# K2 Coordinates as Double Columnar Transposition Keys for K4
#
# USER INSIGHT (2026-03-11): K2 plaintext contains coordinates:
#   "38576 POINT 577844"
# What if POINT is a delimiter separating TWO column orders?
#   Step 1: columns read in order derived from 38576 (width 5)
#   Step 2: columns read in order derived from 577844 (width 6)
#
# This gives a double columnar transposition — exactly like K3's method!
#
# The digits can specify column order in multiple ways:
#   1. Direct: digits as ranking (38576 → rank order [1,4,2,3,0] by sorting)
#   2. Direct sequence: digits as 0-indexed positions
#   3. Modular: digits mod width
#
# Also test: rotation variants, reversed orders, single coordinates as one step
#
# Combined with periodic substitution (Vig/Beau/VBeau) as System 1.
#
# Usage: PYTHONPATH=src python3 -u scripts/two_system/e_k2_coordinate_columnar.py

from __future__ import annotations

import math
import sys
import time
import json
from collections import defaultdict
from itertools import permutations
from typing import List, Tuple, Dict, Set

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
)

# ── K2 coordinate data ───────────────────────────────────────────────────

# K2 plaintext coordinates: 38°57'6.5" N  77°8'44" W
# As carved: "THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS"
# Numeric: 38576.5  77844
# User insight: POINT separates 38576 from 577844
# Alternative split: 385765 and 77844

COORD_SEQUENCES = {
    # Primary hypothesis: POINT separates two column orders
    "38576": [3, 8, 5, 7, 6],
    "577844": [5, 7, 7, 8, 4, 4],
    # Alternative: full latitude / longitude
    "385765": [3, 8, 5, 7, 6, 5],
    "77844": [7, 7, 8, 4, 4],
    # Digits only
    "38576577844": [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],
    # Without the .5: 38576 and 77844
    "38576_77844": [3, 8, 5, 7, 6],  # same as 38576
    # K2 also has: IT WAS TOTALLY INVISIBLE → coordinates
    # Lat digits: 3,8,5,7,6,5  Lon digits: 7,7,8,4,4
}

def digits_to_col_order(digits: List[int]) -> List[int]:
    """Convert a sequence of digits to a column read order.

    Rank the digits: smallest gets order 0, next gets 1, etc.
    Ties broken left-to-right.
    """
    width = len(digits)
    indexed = sorted(range(width), key=lambda i: (digits[i], i))
    # indexed[rank] = original_position → this is the column read order
    return indexed


def digits_to_col_order_direct(digits: List[int], width: int) -> List[int]:
    """Use digits directly as column indices mod width.

    Each digit d maps to column d % width. If this doesn't produce
    a valid permutation, return None.
    """
    order = [d % width for d in digits[:width]]
    if len(set(order)) != width:
        return None
    return order


# ── Columnar transposition ───────────────────────────────────────────────

def columnar_encrypt_positions(length: int, col_order: List[int]) -> List[int]:
    """Position mapping: fwd[i] = j means PT[i] → IT[j]."""
    ncols = len(col_order)
    nrows = math.ceil(length / ncols)
    total = nrows * ncols
    short_cols = total - length

    col_lengths = []
    for col in range(ncols):
        if col >= ncols - short_cols:
            col_lengths.append(nrows - 1)
        else:
            col_lengths.append(nrows)

    col_starts = {}
    pos = 0
    for order_idx in range(ncols):
        col_idx = col_order[order_idx]
        col_starts[col_idx] = pos
        pos += col_lengths[col_idx]

    mapping = [0] * length
    for i in range(length):
        row = i // ncols
        col = i % ncols
        if row < col_lengths[col]:
            mapping[i] = col_starts[col] + row

    return mapping


def undo_columnar(ct: str, col_order: List[int]) -> str:
    """Undo columnar transposition."""
    ncols = len(col_order)
    nrows = math.ceil(len(ct) / ncols)
    total = nrows * ncols
    short_cols = total - len(ct)

    col_lengths = []
    for col in range(ncols):
        if col >= ncols - short_cols:
            col_lengths.append(nrows - 1)
        else:
            col_lengths.append(nrows)

    grid = [[] for _ in range(ncols)]
    pos = 0
    for order_idx in range(ncols):
        col_idx = col_order[order_idx]
        length = col_lengths[col_idx]
        grid[col_idx] = list(ct[pos:pos + length])
        pos += length

    result = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(grid[col]):
                result.append(grid[col][row])
    return "".join(result)


def do_columnar(pt: str, col_order: List[int]) -> str:
    """Apply columnar transposition."""
    ncols = len(col_order)
    nrows = math.ceil(len(pt) / ncols)

    grid = []
    for row in range(nrows):
        grid.append(list(pt[row * ncols: (row + 1) * ncols]))

    result = []
    for order_idx in range(ncols):
        col_idx = col_order[order_idx]
        for row in range(nrows):
            if col_idx < len(grid[row]):
                result.append(grid[row][col_idx])
    return "".join(result)


# ── Substitution helpers ─────────────────────────────────────────────────

def derive_key_vig(ct_char: str, pt_char: str) -> int:
    return (ALPH_IDX[ct_char] - ALPH_IDX[pt_char]) % MOD

def derive_key_beau(ct_char: str, pt_char: str) -> int:
    return (ALPH_IDX[ct_char] + ALPH_IDX[pt_char]) % MOD

def derive_key_vbeau(ct_char: str, pt_char: str) -> int:
    return (ALPH_IDX[pt_char] - ALPH_IDX[ct_char]) % MOD

def decrypt_vig(ct_char: str, key_val: int) -> str:
    return ALPH[(ALPH_IDX[ct_char] - key_val) % MOD]

def decrypt_beau(ct_char: str, key_val: int) -> str:
    return ALPH[(key_val - ALPH_IDX[ct_char]) % MOD]

def decrypt_vbeau(ct_char: str, key_val: int) -> str:
    return ALPH[(ALPH_IDX[ct_char] + key_val) % MOD]

VARIANTS = [
    ("Vig", derive_key_vig, decrypt_vig),
    ("Beau", derive_key_beau, decrypt_beau),
    ("VBeau", derive_key_vbeau, decrypt_vbeau),
]


# ── Load quadgrams ───────────────────────────────────────────────────────

def load_quadgrams(path: str = "data/english_quadgrams.json") -> Dict[str, float]:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def score_quadgrams(text: str, qg: Dict[str, float]) -> float:
    if not qg or len(text) < 4:
        return -15.0
    total = 0.0
    count = 0
    floor = min(qg.values()) - 1.0
    for i in range(len(text) - 3):
        gram = text[i:i+4].upper()
        total += qg.get(gram, floor)
        count += 1
    return total / count if count > 0 else -15.0


# ── Crib consistency check ───────────────────────────────────────────────

def check_crib_consistency(
    intermediate: str,
    trans_positions: List[int],  # fwd[i] = j for the transposition that was applied to PT
    period: int,
    var_name: str,
    derive_fn,
    decrypt_fn,
) -> Tuple[int, str, str]:
    """Check if cribs are consistent given intermediate text and transposition mapping.

    intermediate = text after undoing the OUTER transposition(s) from CT
    trans_positions = forward position mapping of the INNER transposition (PT → IT)

    Model: PT → inner_trans → IT → sub → CT → outer_trans_undo → intermediate
    So: intermediate[j] = sub(IT[j], key) but IT[j] = PT[trans_inv[j]]
    Actually for this function, we want:
        PT → trans(trans_positions) → IT → sub(key, period) → some_CT
    where some_CT = intermediate (after undoing outer transposition from carved CT)

    For each crib pos i: IT[trans_positions[i]] = sub_encrypt(PT[i], key[trans_positions[i] % period])
    which means: intermediate[trans_positions[i]] = sub_encrypt(PT[i], key[trans_positions[i] % period])
    So: key[trans_positions[i] % period] = derive_key(intermediate[trans_positions[i]], PT[i])
    """
    residue_keys: Dict[int, Set[int]] = defaultdict(set)

    for pt_pos in sorted(CRIB_POSITIONS):
        it_pos = trans_positions[pt_pos]
        pt_char = CRIB_DICT[pt_pos]
        it_char = intermediate[it_pos]
        key_val = derive_fn(it_char, pt_char)
        residue_keys[it_pos % period].add(key_val)

    # Count consistent
    n_consistent = 0
    key_by_residue = {}
    for residue, keys in residue_keys.items():
        n_in_class = sum(1 for pp in CRIB_POSITIONS if trans_positions[pp] % period == residue)
        if len(keys) == 1:
            n_consistent += n_in_class
            key_by_residue[residue] = next(iter(keys))
        else:
            key_counts: Dict[int, int] = defaultdict(int)
            for pp in CRIB_POSITIONS:
                if trans_positions[pp] % period == residue:
                    key_counts[derive_fn(intermediate[trans_positions[pp]], CRIB_DICT[pp])] += 1
            n_consistent += max(key_counts.values())

    if n_consistent < 18:
        return n_consistent, "", ""

    if n_consistent < N_CRIBS:
        return n_consistent, "", var_name

    # Full consistency — reconstruct
    key = [0] * period
    for r, kv in key_by_residue.items():
        key[r] = kv

    decrypted_inter = []
    for j in range(CT_LEN):
        decrypted_inter.append(decrypt_fn(intermediate[j], key[j % period]))
    decrypted_text = "".join(decrypted_inter)

    # Undo inner transposition
    inv_positions = [0] * CT_LEN
    for i, j in enumerate(trans_positions):
        inv_positions[j] = i
    plaintext = [""] * CT_LEN
    for j in range(CT_LEN):
        plaintext[inv_positions[j]] = decrypted_text[j]
    plaintext = "".join(plaintext)

    key_chars = "".join(ALPH[k] for k in key)
    return n_consistent, plaintext, f"{var_name} p={period} key={key_chars}"


# ── Main attack ──────────────────────────────────────────────────────────

def attack():
    print("=" * 80)
    print("K2 COORDINATE-DERIVED DOUBLE COLUMNAR × SUBSTITUTION")
    print("Model: PT → trans1(38576) → trans2(577844) → sub(key) → CT")
    print("=" * 80)
    print(f"\nCT: {CT}")
    print(f"Cribs: {N_CRIBS}")
    print()

    qg = load_quadgrams()

    # Verify roundtrip
    test = "HELLOWORLD!"[:10]
    order = [2, 0, 3, 1]
    assert undo_columnar(do_columnar(test, order), order) == test
    print("✓ Roundtrip verified\n")

    results = []
    total_tested = 0
    t_start = time.time()

    # ── Generate all coordinate-derived column orders ─────────────────────

    # Primary split: 38576 / 577844
    seq1_digits = [3, 8, 5, 7, 6]
    seq2_digits = [5, 7, 7, 8, 4, 4]

    # Alternative splits
    alt_splits = [
        ("38576", [3, 8, 5, 7, 6], "577844", [5, 7, 7, 8, 4, 4]),
        ("385765", [3, 8, 5, 7, 6, 5], "77844", [7, 7, 8, 4, 4]),
        ("3857", [3, 8, 5, 7], "6577844", [6, 5, 7, 7, 8, 4, 4]),
        ("38", [3, 8], "576577844", [5, 7, 6, 5, 7, 7, 8, 4, 4]),
        # Single transposition using all digits
        ("38576577844", [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4], None, None),
        # Just first part
        ("38576", [3, 8, 5, 7, 6], None, None),
        # Just second part
        ("577844", [5, 7, 7, 8, 4, 4], None, None),
    ]

    def get_all_orders_from_digits(digits: List[int], label: str) -> List[Tuple[List[int], str]]:
        """Generate multiple column orders from a digit sequence."""
        orders = []
        width = len(digits)

        # Method 1: Rank-based ordering (standard keyword-style)
        rank_order = digits_to_col_order(digits)
        orders.append((rank_order, f"{label}_rank"))

        # Method 2: Inverse of rank ordering
        inv_order = [0] * width
        for i, v in enumerate(rank_order):
            inv_order[v] = i
        orders.append((inv_order, f"{label}_rank_inv"))

        # Method 3: Digits mod width as direct column indices (if valid perm)
        direct = digits_to_col_order_direct(digits, width)
        if direct is not None:
            orders.append((direct, f"{label}_direct"))

        # Method 4: Reversed digit sequence
        rev_digits = digits[::-1]
        rev_order = digits_to_col_order(rev_digits)
        orders.append((rev_order, f"{label}_rev"))

        # Method 5: Rotations of the digit sequence
        for rot in range(1, width):
            rotated = digits[rot:] + digits[:rot]
            rot_order = digits_to_col_order(rotated)
            orders.append((rot_order, f"{label}_rot{rot}"))

        # Method 6: Digits as 0-indexed (subtract min, then rank)
        min_d = min(digits)
        shifted = [d - min_d for d in digits]
        if max(shifted) < width and len(set(shifted)) == width:
            orders.append((shifted, f"{label}_shifted"))

        return orders

    # ── Test all configurations ───────────────────────────────────────────

    print("PHASE 1: Double columnar with K2 coordinate splits")
    print("-" * 60)

    for split_label in alt_splits:
        if split_label[2] is None:
            # Single transposition
            label1, digits1 = split_label[0], split_label[1]
            orders1 = get_all_orders_from_digits(digits1, label1)

            for order1, o1_label in orders1:
                # No second transposition — CT directly goes to sub check
                # Model: PT → trans(order1) → sub → CT
                fwd = columnar_encrypt_positions(CT_LEN, order1)

                for period in range(1, 15):
                    for var_name, derive_fn, decrypt_fn in VARIANTS:
                        residue_keys: Dict[int, Set[int]] = defaultdict(set)
                        for pt_pos in sorted(CRIB_POSITIONS):
                            it_pos = fwd[pt_pos]
                            pt_char = CRIB_DICT[pt_pos]
                            ct_char = CT[it_pos]
                            key_val = derive_fn(ct_char, pt_char)
                            residue_keys[it_pos % period].add(key_val)

                        n_ok = 0
                        for residue, keys in residue_keys.items():
                            n_class = sum(1 for pp in CRIB_POSITIONS if fwd[pp] % period == residue)
                            if len(keys) == 1:
                                n_ok += n_class
                            else:
                                kc = defaultdict(int)
                                for pp in CRIB_POSITIONS:
                                    if fwd[pp] % period == residue:
                                        kc[derive_fn(CT[fwd[pp]], CRIB_DICT[pp])] += 1
                                n_ok += max(kc.values())

                        total_tested += 1
                        if n_ok >= 18:
                            results.append((n_ok, f"single({o1_label}) {var_name} p={period}", ""))
                            if n_ok >= 24:
                                print(f"*** FULL MATCH: single({o1_label}) {var_name} p={period} ***")

            continue

        label1, digits1, label2, digits2 = split_label
        orders1 = get_all_orders_from_digits(digits1, label1)
        orders2 = get_all_orders_from_digits(digits2, label2)

        split_count = 0
        split_best = 0

        for order1, o1_label in orders1:
            for order2, o2_label in orders2:
                # Model: PT → trans1(order1) → trans2(order2) → sub → CT
                # Decrypt: CT → undo_sub → undo_trans2 → undo_trans1 → PT
                # Step 1: undo outer transposition (trans2)
                intermediate = undo_columnar(CT, order2)
                # Now intermediate = sub(trans1(PT))
                # Step 2: check crib consistency with trans1

                fwd1 = columnar_encrypt_positions(CT_LEN, order1)

                for period in range(1, 15):
                    for var_name, derive_fn, decrypt_fn in VARIANTS:
                        residue_keys: Dict[int, Set[int]] = defaultdict(set)
                        for pt_pos in sorted(CRIB_POSITIONS):
                            it_pos = fwd1[pt_pos]
                            pt_char = CRIB_DICT[pt_pos]
                            ct_char = intermediate[it_pos]
                            key_val = derive_fn(ct_char, pt_char)
                            residue_keys[it_pos % period].add(key_val)

                        n_ok = 0
                        key_by_residue = {}
                        for residue, keys in residue_keys.items():
                            n_class = sum(1 for pp in CRIB_POSITIONS if fwd1[pp] % period == residue)
                            if len(keys) == 1:
                                n_ok += n_class
                                key_by_residue[residue] = next(iter(keys))
                            else:
                                kc = defaultdict(int)
                                for pp in CRIB_POSITIONS:
                                    if fwd1[pp] % period == residue:
                                        kc[derive_fn(intermediate[fwd1[pp]], CRIB_DICT[pp])] += 1
                                n_ok += max(kc.values())

                        total_tested += 1
                        split_count += 1

                        if n_ok > split_best:
                            split_best = n_ok

                        if n_ok >= 18:
                            # Reconstruct plaintext
                            pt = ""
                            if n_ok >= 24:
                                key = [0] * period
                                for r, kv in key_by_residue.items():
                                    key[r] = kv
                                dec = []
                                for j in range(CT_LEN):
                                    dec.append(decrypt_fn(intermediate[j], key[j % period]))
                                dec_text = "".join(dec)
                                pt = undo_columnar(dec_text, order1)

                            desc = f"double({o1_label},{o2_label}) {var_name} p={period}"
                            results.append((n_ok, desc, pt))

                            if n_ok >= 24:
                                qg_s = score_quadgrams(pt, qg)
                                print(f"\n*** FULL CRIB MATCH ***")
                                print(f"  {desc}")
                                print(f"  PT: {pt}")
                                print(f"  QG: {qg_s:.4f}")

                # Also try reversed order: trans2 first, then trans1
                intermediate_rev = undo_columnar(CT, order1)
                fwd2 = columnar_encrypt_positions(CT_LEN, order2)

                for period in range(1, 15):
                    for var_name, derive_fn, decrypt_fn in VARIANTS:
                        residue_keys: Dict[int, Set[int]] = defaultdict(set)
                        for pt_pos in sorted(CRIB_POSITIONS):
                            it_pos = fwd2[pt_pos]
                            pt_char = CRIB_DICT[pt_pos]
                            ct_char = intermediate_rev[it_pos]
                            key_val = derive_fn(ct_char, pt_char)
                            residue_keys[it_pos % period].add(key_val)

                        n_ok = 0
                        key_by_residue = {}
                        for residue, keys in residue_keys.items():
                            n_class = sum(1 for pp in CRIB_POSITIONS if fwd2[pp] % period == residue)
                            if len(keys) == 1:
                                n_ok += n_class
                                key_by_residue[residue] = next(iter(keys))
                            else:
                                kc = defaultdict(int)
                                for pp in CRIB_POSITIONS:
                                    if fwd2[pp] % period == residue:
                                        kc[derive_fn(intermediate_rev[fwd2[pp]], CRIB_DICT[pp])] += 1
                                n_ok += max(kc.values())

                        total_tested += 1
                        split_count += 1

                        if n_ok > split_best:
                            split_best = n_ok

                        if n_ok >= 18:
                            pt = ""
                            if n_ok >= 24:
                                key = [0] * period
                                for r, kv in key_by_residue.items():
                                    key[r] = kv
                                dec = []
                                for j in range(CT_LEN):
                                    dec.append(decrypt_fn(intermediate_rev[j], key[j % period]))
                                dec_text = "".join(dec)
                                pt = undo_columnar(dec_text, order2)

                            desc = f"double_rev({o2_label},{o1_label}) {var_name} p={period}"
                            results.append((n_ok, desc, pt))

                            if n_ok >= 24:
                                qg_s = score_quadgrams(pt, qg)
                                print(f"\n*** FULL CRIB MATCH ***")
                                print(f"  {desc}")
                                print(f"  PT: {pt}")
                                print(f"  QG: {qg_s:.4f}")

        print(f"  Split {label1}/{label2}: {split_count:>8,} configs  best_crib={split_best}")
        sys.stdout.flush()

    # ── PHASE 2: Brute-force small widths near coordinate digits ──────────

    print(f"\nPHASE 2: Brute-force double columnar (widths 4-7 × 4-7)")
    print("-" * 60)

    for w1 in range(4, 8):
        for w2 in range(4, 8):
            phase2_count = 0
            phase2_best = 0
            t_p2 = time.time()

            for perm1 in permutations(range(w1)):
                order1 = list(perm1)
                for perm2 in permutations(range(w2)):
                    order2 = list(perm2)

                    # Undo outer trans2
                    intermediate = undo_columnar(CT, order2)
                    fwd1 = columnar_encrypt_positions(CT_LEN, order1)

                    # Check periods 1-7 (K4-relevant range)
                    for period in range(1, 8):
                        for var_name, derive_fn, decrypt_fn in VARIANTS:
                            residue_keys: Dict[int, Set[int]] = defaultdict(set)
                            for pt_pos in sorted(CRIB_POSITIONS):
                                it_pos = fwd1[pt_pos]
                                pt_char = CRIB_DICT[pt_pos]
                                ct_char = intermediate[it_pos]
                                key_val = derive_fn(ct_char, pt_char)
                                residue_keys[it_pos % period].add(key_val)

                            n_ok = 0
                            key_by_residue = {}
                            for residue, keys in residue_keys.items():
                                n_class = sum(1 for pp in CRIB_POSITIONS if fwd1[pp] % period == residue)
                                if len(keys) == 1:
                                    n_ok += n_class
                                    key_by_residue[residue] = next(iter(keys))
                                else:
                                    kc = defaultdict(int)
                                    for pp in CRIB_POSITIONS:
                                        if fwd1[pp] % period == residue:
                                            kc[derive_fn(intermediate[fwd1[pp]], CRIB_DICT[pp])] += 1
                                    n_ok += max(kc.values())

                            total_tested += 1
                            phase2_count += 1

                            if n_ok > phase2_best:
                                phase2_best = n_ok

                            if n_ok >= 20:
                                pt = ""
                                if n_ok >= 24:
                                    key = [0] * period
                                    for r, kv in key_by_residue.items():
                                        key[r] = kv
                                    dec = "".join(decrypt_fn(intermediate[j], key[j % period]) for j in range(CT_LEN))
                                    pt = undo_columnar(dec, order1)
                                desc = f"bf_double(w={w1}:{perm1},w={w2}:{perm2}) {var_name} p={period}"
                                results.append((n_ok, desc, pt))
                                if n_ok >= 24:
                                    qg_s = score_quadgrams(pt, qg)
                                    print(f"\n*** FULL CRIB MATCH ***")
                                    print(f"  {desc}")
                                    print(f"  PT: {pt}")
                                    print(f"  QG: {qg_s:.4f}")

            elapsed = time.time() - t_p2
            print(f"  {w1}×{w2}: {phase2_count:>10,} configs in {elapsed:.1f}s  best={phase2_best}")
            sys.stdout.flush()

    # ── Summary ───────────────────────────────────────────────────────────
    total_elapsed = time.time() - t_start
    print(f"\n{'=' * 80}")
    print(f"TOTAL: {total_tested:,} configs in {total_elapsed:.1f}s")
    print(f"{'=' * 80}\n")

    results.sort(key=lambda x: x[0], reverse=True)

    if results:
        print(f"TOP {min(30, len(results))} RESULTS:")
        print("-" * 100)
        for rank, (crib, desc, pt) in enumerate(results[:30], 1):
            print(f"  #{rank:3d}  crib={crib:2d}/24  {desc}")
            if pt:
                print(f"        PT: {pt[:80]}")
    else:
        print("NO results ≥ threshold")

    print(f"\n{'=' * 80}")
    print("DONE")
    print(f"{'=' * 80}")


if __name__ == "__main__":
    attack()
