#!/usr/bin/env python3
"""
E-S-33b: Mixed-Width Double Columnar + Period-7 Vigenère

Extension of E-S-33: tests width pairs (7,w₂) and (w₁,7) for w₁,w₂ ∈ {5,6,8}.
Also tests periods 2-14 for the (7,7) case (E-S-33 only tested period 7).

Models:
  DC-A: CT = σ₂(σ₁(Vig(PT, key[j%p])))
  DC-B: CT = σ₂(Vig(σ₁(PT), key[i%p]))

Output: results/e_s_33b_mixed_double_columnar.json
"""

import json
import sys
import os
import time
from itertools import permutations
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}


def columnar_perm(col_order, width, length):
    n_rows = (length + width - 1) // width
    n_long = length % width
    if n_long == 0:
        n_long = width
    sigma = [0] * length
    ct_pos = 0
    for col in col_order:
        col_len = n_rows if col < n_long else n_rows - 1
        for row in range(col_len):
            inter_pos = row * width + col
            if inter_pos < length:
                sigma[inter_pos] = ct_pos
                ct_pos += 1
    return sigma


def build_constraint_pairs(crib_pos, period):
    """Build constraint pairs for consistency check at given period."""
    residue_groups = defaultdict(list)
    for j in crib_pos:
        residue_groups[j % period].append(j)
    pairs = []
    pt_diffs = []
    for r in range(period):
        group = residue_groups[r]
        if len(group) >= 2:
            for i in range(1, len(group)):
                pairs.append((group[0], group[i]))
                pt_diffs.append((CRIB_PT[group[0]] - CRIB_PT[group[i]]) % MOD)
    return pairs, pt_diffs


def test_model_a(perms1, perms2, orders1, orders2, period, constraint_pairs, pt_diffs):
    """Test Model DC-A: CT = σ₂(σ₁(Vig(PT, key)))"""
    hits = []
    checked = 0
    for i1, sigma1 in enumerate(perms1):
        inter_pos = {j: sigma1[j] for j in CRIB_POS}
        for i2, sigma2 in enumerate(perms2):
            checked += 1
            fail = False
            for ci, (j1, j2) in enumerate(constraint_pairs):
                ct_pos1 = sigma2[inter_pos[j1]]
                ct_pos2 = sigma2[inter_pos[j2]]
                ct_diff = (CT_NUM[ct_pos1] - CT_NUM[ct_pos2]) % MOD
                if ct_diff != pt_diffs[ci]:
                    fail = True
                    break
            if not fail:
                hits.append((i1, i2))
    return hits, checked


def test_model_b(perms1, perms2, orders1, orders2, period):
    """Test Model DC-B: CT = σ₂(Vig(σ₁(PT), key))"""
    hits = []
    checked = 0
    for i1, sigma1 in enumerate(perms1):
        dcb_residue_groups = defaultdict(list)
        for j in CRIB_POS:
            dcb_residue_groups[sigma1[j] % period].append(j)
        pairs = []
        diffs = []
        for r in range(period):
            group = dcb_residue_groups[r]
            if len(group) >= 2:
                for i in range(1, len(group)):
                    pairs.append((group[0], group[i]))
                    diffs.append((CRIB_PT[group[0]] - CRIB_PT[group[i]]) % MOD)
        if len(pairs) < 10:
            checked += len(perms2)
            continue
        for i2, sigma2 in enumerate(perms2):
            checked += 1
            fail = False
            for ci, (j1, j2) in enumerate(pairs):
                ct_pos1 = sigma2[sigma1[j1]]
                ct_pos2 = sigma2[sigma1[j2]]
                ct_diff = (CT_NUM[ct_pos1] - CT_NUM[ct_pos2]) % MOD
                if ct_diff != diffs[ci]:
                    fail = True
                    break
            if not fail:
                hits.append((i1, i2))
    return hits, checked


def main():
    print("=" * 60)
    print("E-S-33b: Mixed-Width Double Columnar + Vigenère")
    print("=" * 60)

    t0 = time.time()

    # Precompute permutations for each width
    perm_cache = {}
    order_cache = {}
    for w in [5, 6, 7, 8]:
        perms = []
        orders = []
        for ot in permutations(range(w)):
            orders.append(list(ot))
            perms.append(columnar_perm(list(ot), w, N))
        perm_cache[w] = perms
        order_cache[w] = orders
        print(f"  Width {w}: {len(perms)} permutations")

    all_results = []

    # Width combinations to test
    width_pairs = [
        (7, 5), (7, 6), (7, 8),
        (5, 7), (6, 7), (8, 7),
        (5, 5), (5, 6), (6, 5), (6, 6), (6, 8), (8, 6),
    ]

    for w1, w2 in width_pairs:
        perms1 = perm_cache[w1]
        perms2 = perm_cache[w2]
        orders1 = order_cache[w1]
        orders2 = order_cache[w2]
        n_pairs = len(perms1) * len(perms2)

        for period in [7, 5, 6]:
            pairs, diffs = build_constraint_pairs(CRIB_POS, period)
            n_constraints = len(pairs)
            if n_constraints < 10:
                continue

            t_start = time.time()

            # Model DC-A
            hits_a, checked_a = test_model_a(perms1, perms2, orders1, orders2, period, pairs, diffs)
            t_a = time.time() - t_start

            # Model DC-B
            t_b_start = time.time()
            hits_b, checked_b = test_model_b(perms1, perms2, orders1, orders2, period)
            t_b = time.time() - t_b_start

            total_hits = len(hits_a) + len(hits_b)
            print(f"  ({w1},{w2}) p={period}: DC-A={len(hits_a)} DC-B={len(hits_b)}"
                  f"  ({t_a+t_b:.1f}s, {n_pairs:,} pairs, {n_constraints} constraints)",
                  flush=True)

            if hits_a or hits_b:
                all_results.append({
                    "widths": [w1, w2],
                    "period": period,
                    "hits_a": len(hits_a),
                    "hits_b": len(hits_b),
                    "n_constraints": n_constraints,
                    "hit_indices_a": hits_a[:10],
                    "hit_indices_b": hits_b[:10],
                })

    # Also: (7,7) at periods 2-6 and 8-14 (period 7 done in E-S-33)
    print(f"\n  (7,7) at other periods:")
    perms7 = perm_cache[7]
    orders7 = order_cache[7]
    for period in [2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14]:
        pairs, diffs = build_constraint_pairs(CRIB_POS, period)
        n_constraints = len(pairs)
        if n_constraints < 8:
            print(f"  (7,7) p={period}: skipped ({n_constraints} constraints, underdetermined)")
            continue

        t_start = time.time()
        hits_a, checked_a = test_model_a(perms7, perms7, orders7, orders7, period, pairs, diffs)
        t_a = time.time() - t_start

        hits_b, checked_b = test_model_b(perms7, perms7, orders7, orders7, period)
        t_b = time.time() - t_start - t_a

        print(f"  (7,7) p={period}: DC-A={len(hits_a)} DC-B={len(hits_b)}"
              f"  ({t_a+t_b:.1f}s, {n_constraints} constraints)",
              flush=True)

        if hits_a or hits_b:
            all_results.append({
                "widths": [7, 7],
                "period": period,
                "hits_a": len(hits_a),
                "hits_b": len(hits_b),
                "n_constraints": n_constraints,
            })

    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Total time: {elapsed:.1f}s ({elapsed/60:.1f}min)")
    print(f"  Width combos with hits: {len(all_results)}")

    if all_results:
        for r in all_results:
            print(f"    ({r['widths'][0]},{r['widths'][1]}) p={r['period']}: "
                  f"A={r['hits_a']} B={r['hits_b']} constraints={r['n_constraints']}")
    else:
        print(f"  No hits at any width combination. ELIMINATED.")

    verdict = "SIGNAL" if all_results else "NOISE"
    print(f"\n  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_33b_mixed_double_columnar.json", "w") as f:
        json.dump({
            "experiment": "E-S-33b",
            "width_pairs_tested": width_pairs + [(7, 7)],
            "periods_tested": [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
            "total_hits": len(all_results),
            "verdict": verdict,
            "elapsed_seconds": round(elapsed, 1),
            "results": all_results,
        }, f, indent=2)
    print(f"\n  Artifact: results/e_s_33b_mixed_double_columnar.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_33b_mixed_double_columnar.py")


if __name__ == "__main__":
    main()
