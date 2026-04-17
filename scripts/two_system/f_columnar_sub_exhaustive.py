#!/usr/bin/env python3
"""Exhaustive two-layer search: columnar transposition + substitution.

Cipher: Columnar transposition (outer) + Vigenere/Beaufort/VarBeau (inner)
Family: two_system
Status: active
Keyspace: ~6.75B column orderings (widths 5-13), x2 variant groups
Last run: never
Best score: N/A

Tests the hypothesis that K4 = Trans(Sub(PT)) where:
  - Sub is Vigenere, Beaufort, or Variant Beaufort with an unknown key
  - Trans is keyed columnar transposition with unknown width and column order

For each transposition permutation, the substitution key at 24 crib positions
is derived (not searched). Bean constraints filter: equality check alone kills
96.4% of candidates. Vig/VarBeau share identical inequality conditions, so
only two inequality passes are needed (Vig-group and Beau-group).
"""
import sys
import os
import time
import json
import math
from itertools import permutations
from multiprocessing import Pool, cpu_count
from dataclasses import dataclass, asdict
from typing import List, Tuple, Optional

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ, BEAN_LINEAR,
)

# ── Precomputed arrays (module-level for pickling to workers) ───────────

CT_NUMS = tuple(ALPH_IDX[c] for c in CT)
SORTED_CRIB_POS = tuple(sorted(CRIB_DICT.keys()))
PT_NUMS_AT_CRIBS = tuple(ALPH_IDX[CRIB_DICT[p]] for p in SORTED_CRIB_POS)
CRIB_POS_TO_IDX = {p: i for i, p in enumerate(SORTED_CRIB_POS)}

# Bean constraints as (index_a, index_b) into the 24-element key array
_BEAN_EQ_IDX = tuple((CRIB_POS_TO_IDX[a], CRIB_POS_TO_IDX[b]) for a, b in BEAN_EQ)
_BEAN_INEQ_IDX = tuple((CRIB_POS_TO_IDX[a], CRIB_POS_TO_IDX[b]) for a, b in BEAN_INEQ)
_BEAN_LINEAR_IDX = tuple(
    (CRIB_POS_TO_IDX[a], CRIB_POS_TO_IDX[b],
     CRIB_POS_TO_IDX[c], CRIB_POS_TO_IDX[d])
    for a, b, c, d in BEAN_LINEAR
)

# Precompute PT differences for fast inequality checks
# Vig/VarBeau inequality (a,b): CT'[a]-CT'[b] != PT[a]-PT[b] mod 26
# Beau inequality (a,b):        CT'[a]-CT'[b] != PT[b]-PT[a] mod 26
_INEQ_PT_DIFF_VIG = []   # (idx_a, idx_b, forbidden_diff)
_INEQ_PT_DIFF_BEAU = []  # (idx_a, idx_b, forbidden_diff)
for a, b in BEAN_INEQ:
    ia, ib = CRIB_POS_TO_IDX[a], CRIB_POS_TO_IDX[b]
    pa, pb = ALPH_IDX[CRIB_DICT[a]], ALPH_IDX[CRIB_DICT[b]]
    _INEQ_PT_DIFF_VIG.append((ia, ib, (pa - pb) % MOD))
    _INEQ_PT_DIFF_BEAU.append((ia, ib, (pb - pa) % MOD))
_INEQ_PT_DIFF_VIG = tuple(_INEQ_PT_DIFF_VIG)
_INEQ_PT_DIFF_BEAU = tuple(_INEQ_PT_DIFF_BEAU)

# Linear constraints: k[a]-k[b]-k[c]+k[d] = 0 mod 26
# For Vig: k[i] = (ct'[i] - pt[i]) mod 26
# k[a]-k[b]-k[c]+k[d] = (ct'[a]-pt[a]) - (ct'[b]-pt[b]) - (ct'[c]-pt[c]) + (ct'[d]-pt[d])
#                      = (ct'[a]-ct'[b]-ct'[c]+ct'[d]) - (pt[a]-pt[b]-pt[c]+pt[d])
# So we precompute the PT constant term
_LINEAR_VIG = []  # (idx_a, idx_b, idx_c, idx_d, pt_const)
for a, b, c, d in BEAN_LINEAR:
    ia, ib, ic, id_ = (CRIB_POS_TO_IDX[a], CRIB_POS_TO_IDX[b],
                        CRIB_POS_TO_IDX[c], CRIB_POS_TO_IDX[d])
    pa, pb, pc, pd = (ALPH_IDX[CRIB_DICT[a]], ALPH_IDX[CRIB_DICT[b]],
                       ALPH_IDX[CRIB_DICT[c]], ALPH_IDX[CRIB_DICT[d]])
    pt_const = (pa - pb - pc + pd) % MOD
    _LINEAR_VIG.append((ia, ib, ic, id_, pt_const))
_LINEAR_VIG = tuple(_LINEAR_VIG)

# For Beaufort: k[i] = (ct'[i] + pt[i]) mod 26
# k[a]-k[b]-k[c]+k[d] = (ct'[a]+pt[a]) - (ct'[b]+pt[b]) - (ct'[c]+pt[c]) + (ct'[d]+pt[d])
_LINEAR_BEAU = []
for a, b, c, d in BEAN_LINEAR:
    ia, ib, ic, id_ = (CRIB_POS_TO_IDX[a], CRIB_POS_TO_IDX[b],
                        CRIB_POS_TO_IDX[c], CRIB_POS_TO_IDX[d])
    pa, pb, pc, pd = (ALPH_IDX[CRIB_DICT[a]], ALPH_IDX[CRIB_DICT[b]],
                       ALPH_IDX[CRIB_DICT[c]], ALPH_IDX[CRIB_DICT[d]])
    pt_const = (pa - pb - pc + pd) % MOD  # same for Beau! k=c+p vs k=c-p, diff cancels
    _LINEAR_BEAU.append((ia, ib, ic, id_, pt_const))
_LINEAR_BEAU = tuple(_LINEAR_BEAU)

# Crib positions decomposed into (row, col) for each width
# For a crib at position pos with grid width w:
#   row = pos // w, col = pos % w
#   inv_perm[pos] = col_start_in_ct[col] + row
# We just need col_start_in_ct[col] + row for each crib position.

# Bean equality positions
_BEAN_EQ_POS = tuple((a, b) for a, b in BEAN_EQ)  # actual positions (27, 65)

# Configuration
MIN_WIDTH = 5
MAX_WIDTH = 13
WIDTHS = list(range(MIN_WIDTH, MAX_WIDTH + 1))


# ── Optimized inner loop ─────────────────────────────────────────────────

def _precompute_width(width: int):
    """Precompute per-width constants."""
    n = CT_LEN
    n_full_rows = n // width
    n_extra = n % width
    col_lengths = tuple(n_full_rows + (1 if c < n_extra else 0) for c in range(width))

    # For each crib position, its (row, col) in the grid
    crib_row_col = tuple((pos // width, pos % width) for pos in SORTED_CRIB_POS)

    # Bean equality: positions 27 and 65
    eq_a, eq_b = _BEAN_EQ_POS[0]
    eq_a_row, eq_a_col = eq_a // width, eq_a % width
    eq_b_row, eq_b_col = eq_b // width, eq_b % width

    return col_lengths, crib_row_col, (eq_a_row, eq_a_col, eq_b_row, eq_b_col)


def worker_fn(args):
    """Worker: scan assigned slice of permutations for one width."""
    width, worker_id, n_workers = args
    col_lengths, crib_row_col, eq_info = _precompute_width(width)
    eq_a_row, eq_a_col, eq_b_row, eq_b_col = eq_info

    hits = []
    checked = 0
    eq_pass = 0

    for idx, col_order in enumerate(permutations(range(width))):
        if idx % n_workers != worker_id:
            continue
        checked += 1

        # Build col_start_in_ct from this column order
        col_start = [0] * width
        offset = 0
        for read_idx in range(width):
            ci = col_order[read_idx]
            col_start[ci] = offset
            offset += col_lengths[ci]

        # ── Fast Bean equality check ──────────────────────────────────
        # CT value at inv_perm[27] and inv_perm[65]
        ct_at_eq_a = CT_NUMS[col_start[eq_a_col] + eq_a_row]
        ct_at_eq_b = CT_NUMS[col_start[eq_b_col] + eq_b_row]
        if ct_at_eq_a != ct_at_eq_b:
            continue

        eq_pass += 1

        # ── Compute CT values at all 24 crib positions ────────────────
        ct_at_cribs = tuple(
            CT_NUMS[col_start[col] + row]
            for row, col in crib_row_col
        )

        # ── Check Vig/VarBeau group (same inequality condition) ───────
        vig_pass = True
        # Inequalities: ct_diff != pt_diff
        for ia, ib, forbidden in _INEQ_PT_DIFF_VIG:
            if (ct_at_cribs[ia] - ct_at_cribs[ib]) % MOD == forbidden:
                vig_pass = False
                break
        if vig_pass:
            # Linear: (ct[a]-ct[b]-ct[c]+ct[d]) mod 26 == pt_const
            for ia, ib, ic, id_, pt_const in _LINEAR_VIG:
                ct_lin = (ct_at_cribs[ia] - ct_at_cribs[ib]
                          - ct_at_cribs[ic] + ct_at_cribs[id_]) % MOD
                if ct_lin != pt_const:
                    vig_pass = False
                    break

        # ── Check Beaufort group ──────────────────────────────────────
        beau_pass = True
        for ia, ib, forbidden in _INEQ_PT_DIFF_BEAU:
            if (ct_at_cribs[ia] - ct_at_cribs[ib]) % MOD == forbidden:
                beau_pass = False
                break
        if beau_pass:
            for ia, ib, ic, id_, pt_const in _LINEAR_BEAU:
                ct_lin = (ct_at_cribs[ia] - ct_at_cribs[ib]
                          - ct_at_cribs[ic] + ct_at_cribs[id_]) % MOD
                if ct_lin != pt_const:
                    beau_pass = False
                    break

        if not vig_pass and not beau_pass:
            continue

        # ── Bean full pass! Record hit. ───────────────────────────────
        for variant_label, passed in [("vigenere", vig_pass),
                                       ("beaufort", beau_pass),
                                       ("var_beaufort", vig_pass)]:
            if not passed:
                continue
            # Derive full key at cribs
            keys = []
            for i in range(N_CRIBS):
                c = ct_at_cribs[i]
                p = PT_NUMS_AT_CRIBS[i]
                if variant_label == "vigenere":
                    keys.append((c - p) % MOD)
                elif variant_label == "beaufort":
                    keys.append((c + p) % MOD)
                else:
                    keys.append((p - c) % MOD)
            keys = tuple(keys)

            # Try periodic key extension
            periodic = _try_periodic(keys)

            # Full decrypt for complete periodic keys
            best_pt, best_eng = None, 0.0
            inv_perm = _build_full_inv_perm(width, col_order, col_start)
            for period, full_key in periodic:
                if any(k is None for k in full_key):
                    continue
                pt = _decrypt(inv_perm, period, full_key, variant_label)
                eng = _english_score(pt)
                if eng > best_eng:
                    best_eng = eng
                    best_pt = pt

            hits.append({
                "width": width,
                "col_order": col_order,
                "variant": variant_label,
                "keys_at_cribs": keys,
                "periodic_periods": [p for p, _ in periodic],
                "best_plaintext": best_pt,
                "english_score": best_eng,
            })

    return hits, checked, eq_pass


def _build_full_inv_perm(width, col_order, col_start):
    n = CT_LEN
    n_full_rows = n // width
    n_extra = n % width
    col_lens = [n_full_rows + (1 if c < n_extra else 0) for c in range(width)]
    inv_perm = [0] * n
    for row in range(n_full_rows + 1):
        for col in range(width):
            pos = row * width + col
            if pos >= n:
                break
            if row >= col_lens[col]:
                continue
            inv_perm[pos] = col_start[col] + row
    return tuple(inv_perm)


def _try_periodic(keys_at_cribs, max_period=26):
    results = []
    for period in range(1, max_period + 1):
        residue_vals = {}
        ok = True
        for i, pos in enumerate(SORTED_CRIB_POS):
            r = pos % period
            if r not in residue_vals:
                residue_vals[r] = keys_at_cribs[i]
            elif residue_vals[r] != keys_at_cribs[i]:
                ok = False
                break
        if ok:
            full_key = [None] * period
            for i, pos in enumerate(SORTED_CRIB_POS):
                full_key[pos % period] = keys_at_cribs[i]
            results.append((period, tuple(full_key)))
    return results


def _decrypt(inv_perm, period, key, variant):
    result = []
    for pos in range(CT_LEN):
        c = CT_NUMS[inv_perm[pos]]
        k = key[pos % period]
        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        else:
            p = (c + k) % MOD
        result.append(ALPH[p])
    return ''.join(result)


_COMMON_BIGRAMS = frozenset({
    'TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND',
    'TI', 'ES', 'OR', 'TE', 'OF', 'ED', 'IS', 'IT', 'AL', 'AR',
    'ST', 'TO', 'NT', 'NG', 'SE', 'HA', 'AS', 'OU', 'IO', 'LE',
})


def _english_score(text):
    if not text:
        return 0.0
    hits = sum(1 for i in range(len(text) - 1) if text[i:i+2] in _COMMON_BIGRAMS)
    return hits / (len(text) - 1)


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    n_workers = max(1, cpu_count() - 2)
    print(f"=== Two-Layer Exhaustive: Columnar + Substitution ===")
    print(f"Workers: {n_workers}")
    print(f"Widths: {MIN_WIDTH}-{MAX_WIDTH}")
    print(f"Bean equality filter: ~3.6% pass rate")
    print(f"Variant groups: Vig/VarBeau (shared ineq), Beaufort (separate ineq)")
    print()

    total_orderings = sum(math.factorial(w) for w in WIDTHS)
    print(f"Total column orderings: {total_orderings:,}")
    print()

    all_hits = []
    total_checked = 0
    total_eq_pass = 0
    grand_start = time.time()

    for width in WIDTHS:
        n_perms = math.factorial(width)
        print(f"Width {width:2d}: {n_perms:>13,d} orderings ", end="", flush=True)
        w_start = time.time()

        if n_perms <= 50000:
            results = [worker_fn((width, 0, 1))]
        else:
            args = [(width, wid, n_workers) for wid in range(n_workers)]
            with Pool(n_workers) as pool:
                results = list(pool.imap_unordered(worker_fn, args))

        w_hits = []
        w_checked = 0
        w_eq_pass = 0
        for hits, checked, eq_pass in results:
            w_hits.extend(hits)
            w_checked += checked
            w_eq_pass += eq_pass

        elapsed = time.time() - w_start
        rate = n_perms / elapsed if elapsed > 0 else 0
        print(f"| {w_eq_pass:>8,d} eq_pass | {len(w_hits):4d} full_pass | "
              f"{elapsed:7.1f}s ({rate:>10,.0f}/s)")

        all_hits.extend(w_hits)
        total_checked += w_checked
        total_eq_pass += w_eq_pass

        if w_hits:
            best = max(w_hits, key=lambda h: h["english_score"])
            print(f"    Best: eng={best['english_score']:.4f} "
                  f"var={best['variant']} order={best['col_order']} "
                  f"periods={best['periodic_periods']}")
            if best.get("best_plaintext"):
                print(f"    PT: {best['best_plaintext']}")

    grand_elapsed = time.time() - grand_start
    print()
    print(f"{'='*70}")
    print(f"COMPLETE in {grand_elapsed:.1f}s ({grand_elapsed/60:.1f} min)")
    print(f"Orderings tested: {total_orderings:,}")
    print(f"Bean equality survivors: {total_eq_pass:,}")
    print(f"Full Bean+linear passes: {len(all_hits)}")
    print(f"{'='*70}")

    # Save results
    results_path = os.path.join(_ROOT, "results", "f_columnar_sub_exhaustive.json")
    result_obj = {
        "campaign": "f_columnar_sub_exhaustive",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "widths": WIDTHS,
        "total_orderings": total_orderings,
        "total_eq_pass": total_eq_pass,
        "total_full_pass": len(all_hits),
        "elapsed_seconds": grand_elapsed,
        "workers": n_workers,
    }

    if all_hits:
        all_hits.sort(key=lambda h: h["english_score"], reverse=True)
        result_obj["hits"] = all_hits[:100]
        print(f"\n=== Top 20 by English score ===")
        for i, h in enumerate(all_hits[:20]):
            print(f"  {i+1:3d}. w={h['width']} eng={h['english_score']:.4f} "
                  f"var={h['variant']} periods={h['periodic_periods']}")
            if h.get("best_plaintext"):
                print(f"       PT: {h['best_plaintext']}")
    else:
        result_obj["result"] = "ELIMINATED"
        result_obj["scope"] = (
            f"Columnar transposition (widths {MIN_WIDTH}-{MAX_WIDTH}, ALL column "
            f"orderings) composed with Vigenere/Beaufort/Variant Beaufort. "
            f"Zero configurations pass full Bean constraints (equality + 242 "
            f"inequalities + 101 linear)."
        )
        print(f"\nZERO full Bean passes.")
        print(f"ELIMINATED: Trans(Sub(PT)) with columnar widths {MIN_WIDTH}-{MAX_WIDTH}")

    with open(results_path, "w") as f:
        json.dump(result_obj, f, indent=2)
    print(f"\nResults: {results_path}")


if __name__ == "__main__":
    main()
