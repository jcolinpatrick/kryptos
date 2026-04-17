#!/usr/bin/env python3
"""Pilot: opposite peel order -- Sub(ColumnarTrans(PT)).

Cipher: Substitution (outer) + Columnar transposition (inner)
Family: two_system
Status: active
Keyspace: pilot widths 5-10
Last run: never
Best score: N/A

Tests the hypothesis that K4 = Sub(Trans(PT)) where:
  - Trans is keyed columnar transposition (inner, applied first)
  - Sub is Vigenere, Beaufort, or Variant Beaufort (outer, applied second)

Decryption order: undo Sub first, then undo Trans.
  intermediate = inv_Sub(CT, key)    -- need the key
  PT = inv_Trans(intermediate)       -- need the transposition

Constraint structure (different from Trans(Sub(PT))):
  At crib position i, PT[i] is known. After transposition, PT[i] was at
  position perm[i] in the intermediate text. So:
    intermediate[perm[i]] = Sub(PT[i], key[perm[i]])
  But also: intermediate[j] = inv_Sub(CT[j], key[j]) for all j.
  So: inv_Sub(CT[perm[i]], key[perm[i]]) = PT[i]

  This determines key[perm[i]] from CT[perm[i]] and PT[i]:
    Vig:     key[perm[i]] = (CT[perm[i]] - PT[i]) mod 26
    Beau:    key[perm[i]] = (CT[perm[i]] + PT[i]) mod 26  (since Beau: PT = (K-C) -> K = C+P)
    VarBeau: key[perm[i]] = (PT[i] - CT[perm[i]]) mod 26

  The key values are at PERMUTED positions perm[i], not at crib positions i.
  Bean constraints are about key[27] = key[65], etc. -- positions in the
  intermediate (= ciphertext) space, not the plaintext space.

  So Bean equality requires: key[27] = key[65].
  We know key values at perm[crib_positions]. For Bean eq to apply, we need
  positions 27 and 65 to be in the set {perm[i] : i in crib_positions}.

  This is a fundamentally different constraint structure: Bean applies only
  when the transposition maps crib positions ONTO Bean-constrained positions.
"""
import sys
import os
import time
import json
import math
from itertools import permutations
from multiprocessing import Pool, cpu_count
from typing import List, Tuple, Optional, Dict, Set

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ, BEAN_LINEAR,
)

CT_NUMS = tuple(ALPH_IDX[c] for c in CT)
SORTED_CRIB_POS = tuple(sorted(CRIB_DICT.keys()))
PT_NUMS_AT_CRIBS = tuple(ALPH_IDX[CRIB_DICT[p]] for p in SORTED_CRIB_POS)
CRIB_POS_SET = frozenset(SORTED_CRIB_POS)

# Bean equality positions (in the key/intermediate space)
BEAN_EQ_POSITIONS = set()
for a, b in BEAN_EQ:
    BEAN_EQ_POSITIONS.add(a)
    BEAN_EQ_POSITIONS.add(b)

# All Bean-constrained positions (positions that appear in any Bean constraint)
BEAN_ALL_POSITIONS = set()
for a, b in BEAN_EQ:
    BEAN_ALL_POSITIONS.update([a, b])
for a, b in BEAN_INEQ:
    BEAN_ALL_POSITIONS.update([a, b])
for a, b, c, d in BEAN_LINEAR:
    BEAN_ALL_POSITIONS.update([a, b, c, d])

# Note: Bean-constrained positions ARE the crib positions (by construction)
assert BEAN_ALL_POSITIONS == set(SORTED_CRIB_POS), "Bean positions should be crib positions"

MIN_WIDTH = 5
MAX_WIDTH = 13  # Extended to match Trans(Sub(PT)) scope
WIDTHS = list(range(MIN_WIDTH, MAX_WIDTH + 1))
VARIANTS = ("vigenere", "beaufort", "var_beaufort")


def build_columnar_perm(width: int, col_order: tuple) -> tuple:
    """Build the FORWARD transposition permutation.

    For Sub(Trans(PT)):
    - Trans writes PT into rows of width, reads columns in col_order
    - intermediate[j] = PT[perm[j]] where perm is the gather permutation
    - So PT[i] is at intermediate position inv_perm[i]

    Returns perm such that intermediate[j] = PT[perm[j]].
    Also returns inv_perm such that PT[i] = intermediate[inv_perm[i]].
    """
    n = CT_LEN
    n_full_rows = n // width
    n_extra = n % width
    col_lengths = [n_full_rows + (1 if c < n_extra else 0) for c in range(width)]

    col_start_in_intermediate = [0] * width
    offset = 0
    for read_idx in range(width):
        ci = col_order[read_idx]
        col_start_in_intermediate[ci] = offset
        offset += col_lengths[ci]

    # inv_perm[pt_pos] = intermediate_pos
    # For PT position (row, col): intermediate_pos = col_start[col] + row
    inv_perm = [0] * n
    perm = [0] * n  # perm[intermediate_pos] = pt_pos
    for row in range(n_full_rows + 1):
        for col in range(width):
            pt_pos = row * width + col
            if pt_pos >= n:
                break
            if row >= col_lengths[col]:
                continue
            inter_pos = col_start_in_intermediate[col] + row
            inv_perm[pt_pos] = inter_pos
            perm[inter_pos] = pt_pos

    return tuple(perm), tuple(inv_perm)


def worker_fn(args):
    """Worker: scan assigned slice for one width."""
    width, worker_id, n_workers = args

    n = CT_LEN
    n_full_rows = n // width
    n_extra = n % width
    col_lengths = tuple(n_full_rows + (1 if c < n_extra else 0) for c in range(width))

    hits = []
    checked = 0
    key_derivable = 0
    bean_eq_pass = 0
    bean_full_pass = 0

    for idx, col_order in enumerate(permutations(range(width))):
        if idx % n_workers != worker_id:
            continue
        checked += 1

        # Build col_start for this order
        col_start = [0] * width
        offset = 0
        for read_idx in range(width):
            ci = col_order[read_idx]
            col_start[ci] = offset
            offset += col_lengths[ci]

        # inv_perm[crib_pos] = intermediate_pos where PT[crib_pos] lands
        # Key is defined at intermediate positions (= CT positions).
        # We know key[inv_perm[crib_pos]] for each crib position.
        # Bean constraints are about key[bean_pos] for bean_pos in crib_positions.
        #
        # We need: for each Bean-constrained position b, there exists a crib
        # position c such that inv_perm[c] = b (i.e., the transposition maps
        # crib position c to Bean-constrained position b).
        #
        # Since Bean positions = crib positions, we need:
        # For each crib position b, exists crib position c with inv_perm[c] = b.
        # i.e., the set {inv_perm[c] : c in crib_positions} ⊇ crib_positions.
        # i.e., the transposition maps crib positions onto crib positions.

        # Compute where each crib position maps to in intermediate space
        mapped = set()
        crib_to_inter = {}
        for crib_pos in SORTED_CRIB_POS:
            row = crib_pos // width
            col = crib_pos % width
            if row >= col_lengths[col]:
                # This position doesn't exist in the grid (shouldn't happen for valid pos < n)
                continue
            inter_pos = col_start[col] + row
            mapped.add(inter_pos)
            crib_to_inter[crib_pos] = inter_pos

        # Check: do the mapped positions cover all Bean-constrained positions?
        if not CRIB_POS_SET.issubset(mapped):
            # Can't evaluate all Bean constraints -- some key positions unknown
            continue

        key_derivable += 1

        # Build the key-value map: key[inter_pos] derived from CT[inter_pos] and PT[crib_pos]
        # For each crib position c: key[inv_perm[c]] = f(CT[inv_perm[c]], PT[c])
        # But we need key[b] for each Bean position b. We need to find which
        # crib position c maps to b: inv_perm[c] = b.
        inter_to_crib = {}  # inter_pos -> crib_pos (inverse of crib_to_inter)
        for c, ip in crib_to_inter.items():
            inter_to_crib[ip] = c

        for variant in VARIANTS:
            # Compute key at all crib/Bean positions
            key_at_bean = {}  # bean_pos -> key_value
            for bean_pos in SORTED_CRIB_POS:
                if bean_pos not in inter_to_crib:
                    break  # shouldn't happen if coverage check passed
                source_crib = inter_to_crib[bean_pos]
                ct_val = CT_NUMS[bean_pos]
                pt_val = ALPH_IDX[CRIB_DICT[source_crib]]
                if variant == "vigenere":
                    k = (ct_val - pt_val) % MOD
                elif variant == "beaufort":
                    k = (ct_val + pt_val) % MOD
                else:
                    k = (pt_val - ct_val) % MOD
                key_at_bean[bean_pos] = k
            else:
                # All positions computed
                pass

            if len(key_at_bean) < N_CRIBS:
                continue

            # Check Bean equality
            eq_ok = True
            for a, b in BEAN_EQ:
                if key_at_bean[a] != key_at_bean[b]:
                    eq_ok = False
                    break
            if not eq_ok:
                continue

            bean_eq_pass += 1

            # Check Bean inequalities
            ineq_ok = True
            for a, b in BEAN_INEQ:
                if key_at_bean[a] == key_at_bean[b]:
                    ineq_ok = False
                    break
            if not ineq_ok:
                continue

            # Check Bean linear
            lin_ok = True
            for a, b, c, d in BEAN_LINEAR:
                if (key_at_bean[a] - key_at_bean[b] - key_at_bean[c] + key_at_bean[d]) % MOD != 0:
                    lin_ok = False
                    break
            if not lin_ok:
                continue

            bean_full_pass += 1

            # Full Bean pass! Record hit.
            keys_tuple = tuple(key_at_bean[p] for p in SORTED_CRIB_POS)
            hits.append({
                "width": width,
                "col_order": col_order,
                "variant": variant,
                "keys_at_bean_positions": keys_tuple,
                "mapped_positions": {str(c): crib_to_inter[c] for c in SORTED_CRIB_POS},
            })

    return hits, checked, key_derivable, bean_eq_pass, bean_full_pass


def main():
    n_workers = max(1, cpu_count() - 2)
    print(f"=== Two-Layer Pilot: Sub(ColumnarTrans(PT)) ===")
    print(f"Workers: {n_workers}")
    print(f"Widths: {MIN_WIDTH}-{MAX_WIDTH}")
    print(f"Constraint: Bean applies only when transposition maps crib->crib positions")
    print()

    total_orderings = sum(math.factorial(w) for w in WIDTHS)
    print(f"Total column orderings: {total_orderings:,}")
    print()

    all_hits = []
    grand_totals = {"checked": 0, "derivable": 0, "eq_pass": 0, "full_pass": 0}
    grand_start = time.time()

    for width in WIDTHS:
        n_perms = math.factorial(width)
        print(f"Width {width:2d}: {n_perms:>10,d} orderings ", end="", flush=True)
        w_start = time.time()

        if n_perms <= 50000:
            results = [worker_fn((width, 0, 1))]
        else:
            args = [(width, wid, n_workers) for wid in range(n_workers)]
            with Pool(n_workers) as pool:
                results = list(pool.imap_unordered(worker_fn, args))

        w_hits, w_checked, w_deriv, w_eq, w_full = [], 0, 0, 0, 0
        for hits, checked, derivable, eq_pass, full_pass in results:
            w_hits.extend(hits)
            w_checked += checked
            w_deriv += derivable
            w_eq += eq_pass
            w_full += full_pass

        elapsed = time.time() - w_start
        rate = n_perms / elapsed if elapsed > 0 else 0
        print(f"| {w_deriv:>8,d} derivable | {w_eq:>6d} eq | "
              f"{w_full:4d} full | {elapsed:6.1f}s ({rate:>10,.0f}/s)")

        all_hits.extend(w_hits)
        grand_totals["checked"] += w_checked
        grand_totals["derivable"] += w_deriv
        grand_totals["eq_pass"] += w_eq
        grand_totals["full_pass"] += w_full

        if w_hits:
            for h in w_hits[:3]:
                print(f"    HIT: var={h['variant']} order={h['col_order']}")

    grand_elapsed = time.time() - grand_start
    print()
    print(f"{'='*70}")
    print(f"COMPLETE in {grand_elapsed:.1f}s ({grand_elapsed/60:.1f} min)")
    print(f"Orderings tested: {total_orderings:,}")
    print(f"Key-derivable (crib->crib mapping): {grand_totals['derivable']:,}")
    print(f"Bean equality passes: {grand_totals['eq_pass']:,}")
    print(f"Full Bean passes: {grand_totals['full_pass']}")
    print(f"{'='*70}")

    # Save
    results_path = os.path.join(_ROOT, "results", "f_sub_columnar_pilot.json")
    result_obj = {
        "campaign": "f_sub_columnar_pilot",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "widths": WIDTHS,
        "total_orderings": total_orderings,
        **grand_totals,
        "elapsed_seconds": grand_elapsed,
        "workers": n_workers,
    }
    if all_hits:
        result_obj["hits"] = all_hits[:100]
    else:
        result_obj["result"] = "ELIMINATED" if grand_totals["derivable"] > 0 else "STRUCTURAL_FILTER"

    with open(results_path, "w") as f:
        json.dump(result_obj, f, indent=2)
    print(f"\nResults: {results_path}")

    if not all_hits:
        if grand_totals["derivable"] == 0:
            print(f"\nNote: ZERO orderings produced a crib->crib position mapping.")
            print(f"This means no columnar transposition at widths {MIN_WIDTH}-{MAX_WIDTH}")
            print(f"maps all 24 crib positions onto crib positions (structural impossibility).")
        else:
            print(f"\nZERO Bean passes among {grand_totals['derivable']:,} derivable configs.")


if __name__ == "__main__":
    main()
