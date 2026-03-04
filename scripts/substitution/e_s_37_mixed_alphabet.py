#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: substitution
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-37: Mixed Alphabet Cipher + Columnar Transposition

CRITICAL REFRAME: All prior tests assume Vigenère (CT-PT = const per residue).
Mixed alphabet ciphers use a different permutation for each period position:
  CT[σ(j)] = α_{j%p}(PT[j])

The constraint from cribs is WEAKER than Vigenère:
  1. EQUALITY: if PT[j1] = PT[j2] and j1%p == j2%p, then CT[σ(j1)] = CT[σ(j2)]
  2. INJECTIVITY: if PT[j1] ≠ PT[j2] and j1%p == j2%p, then CT[σ(j1)] ≠ CT[σ(j2)]

For period 7 with our 24 cribs:
  Equality constraints (same PT letter, same residue):
    - Residue 0: pos 28,70 both PT=N → CT[σ(28)] = CT[σ(70)]
    - Residue 2: pos 30,65 both PT=R → CT[σ(30)] = CT[σ(65)]
    - Residue 3: pos 24,31 both PT=T → CT[σ(24)] = CT[σ(31)]
  Injectivity: many pairwise-distinct constraints per residue

Tests:
  Phase 1: Single width-7 columnar + mixed alphabet (5040 orderings)
  Phase 2: Double width-7 columnar + mixed alphabet (5040² pairs)
  Phase 3: Width-7 columnar + mixed alphabet at periods 5-10

Output: results/e_s_37_mixed_alphabet.json
"""

import json
import sys
import os
import time
from collections import defaultdict
from itertools import permutations

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


def build_mixed_alphabet_constraints(period):
    """Build equality and injectivity constraints for mixed alphabet at given period."""
    residue_groups = defaultdict(list)
    for j in CRIB_POS:
        residue_groups[j % period].append(j)

    # Equality constraints: same PT value in same residue
    eq_constraints = []  # (j1, j2) where CT[σ(j1)] must equal CT[σ(j2)]
    ineq_constraints = []  # (j1, j2) where CT[σ(j1)] must differ from CT[σ(j2)]

    for r in range(period):
        group = residue_groups[r]
        # Group by PT value within this residue
        pt_groups = defaultdict(list)
        for j in group:
            pt_groups[CRIB_PT[j]].append(j)

        # Equality: positions with same PT value must have same CT value
        for pt_val, positions in pt_groups.items():
            for i in range(1, len(positions)):
                eq_constraints.append((positions[0], positions[i]))

        # Injectivity: positions with different PT values must have different CT values
        pt_vals = list(pt_groups.keys())
        for i in range(len(pt_vals)):
            for j in range(i + 1, len(pt_vals)):
                # Pick one representative from each PT group
                for p1 in pt_groups[pt_vals[i]]:
                    for p2 in pt_groups[pt_vals[j]]:
                        ineq_constraints.append((p1, p2))

    return eq_constraints, ineq_constraints, residue_groups


def check_mixed_alphabet(sigma, eq_constraints, ineq_constraints):
    """Check if transposition σ is compatible with mixed alphabet constraints."""
    # Check equality constraints first (stronger filter)
    for j1, j2 in eq_constraints:
        if CT_NUM[sigma[j1]] != CT_NUM[sigma[j2]]:
            return False

    # Check injectivity constraints
    for j1, j2 in ineq_constraints:
        if CT_NUM[sigma[j1]] == CT_NUM[sigma[j2]]:
            return False

    return True


def recover_alphabets(sigma, period, residue_groups):
    """Recover the mixed alphabets from a valid σ."""
    alphabets = {}
    for r in range(period):
        alpha = {}
        for j in residue_groups[r]:
            pt_val = CRIB_PT[j]
            ct_val = CT_NUM[sigma[j]]
            if pt_val in alpha:
                assert alpha[pt_val] == ct_val
            else:
                alpha[pt_val] = ct_val
        alphabets[r] = alpha
    return alphabets


def decode_plaintext(sigma, period, alphabets):
    """Attempt to decode plaintext (only positions where alphabet is known)."""
    # Build inverse alphabets
    inv_alphas = {}
    for r, alpha in alphabets.items():
        inv_alphas[r] = {v: k for k, v in alpha.items()}

    pt = ['?'] * N
    n_decoded = 0
    for j in range(N):
        r = j % period
        ct_val = CT_NUM[sigma[j]]
        if ct_val in inv_alphas.get(r, {}):
            pt[j] = chr(inv_alphas[r][ct_val] + ord('A'))
            n_decoded += 1
        else:
            pt[j] = '?'

    return ''.join(pt), n_decoded


def main():
    print("=" * 60)
    print("E-S-37: Mixed Alphabet Cipher + Columnar Transposition")
    print("=" * 60)

    t0 = time.time()

    # =========================================================
    # Phase 1: Single width-7 columnar at various periods
    # =========================================================
    all_results = []

    for period in [7, 5, 6, 8, 9, 10]:
        eq_con, ineq_con, res_groups = build_mixed_alphabet_constraints(period)
        print(f"\n{'='*60}")
        print(f"Period {period}: {len(eq_con)} equality + {len(ineq_con)} injectivity constraints")
        print(f"{'='*60}")

        n_pass = 0
        n_tested = 0

        for order_tuple in permutations(range(7)):
            order = list(order_tuple)
            sigma = columnar_perm(order, 7, N)
            n_tested += 1

            if check_mixed_alphabet(sigma, eq_con, ineq_con):
                n_pass += 1
                alphabets = recover_alphabets(sigma, period, res_groups)
                pt_str, n_decoded = decode_plaintext(sigma, period, alphabets)

                result = {
                    "period": period,
                    "width": 7,
                    "order": order,
                    "n_decoded": n_decoded,
                    "plaintext": pt_str,
                    "alphabets": {str(r): {chr(k+65): chr(v+65) for k,v in a.items()}
                                  for r, a in alphabets.items()},
                }
                all_results.append(result)

                if n_pass <= 5 or n_decoded > 50:
                    print(f"  *** PASS: order={order} decoded={n_decoded}/97"
                          f" PT={pt_str[:60]}")

        print(f"  Single columnar w=7: {n_pass}/{n_tested} pass mixed alphabet constraints")

        # Also test identity transposition
        identity = list(range(N))
        if check_mixed_alphabet(identity, eq_con, ineq_con):
            alphabets = recover_alphabets(identity, period, res_groups)
            pt_str, n_decoded = decode_plaintext(identity, period, alphabets)
            print(f"  Identity σ passes! decoded={n_decoded}/97 PT={pt_str[:60]}")

    # =========================================================
    # Phase 2: Double width-7 columnar at period 7
    # =========================================================
    print(f"\n{'='*60}")
    print(f"Phase 2: Double columnar (7,7) + mixed alphabet at period 7")
    print(f"{'='*60}")

    eq_con, ineq_con, res_groups = build_mixed_alphabet_constraints(7)

    # Precompute all width-7 permutations
    all_perms = []
    all_orders = []
    for order_tuple in permutations(range(7)):
        order = list(order_tuple)
        all_perms.append(columnar_perm(order, 7, N))
        all_orders.append(order)

    dc_pass = 0
    dc_checked = 0

    for i1, sigma1 in enumerate(all_perms):
        for i2, sigma2 in enumerate(all_perms):
            dc_checked += 1

            # Composed permutation σ₂∘σ₁
            # Check equality constraints
            fail = False
            for j1, j2 in eq_con:
                if CT_NUM[sigma2[sigma1[j1]]] != CT_NUM[sigma2[sigma1[j2]]]:
                    fail = True
                    break
            if fail:
                continue

            # Check injectivity constraints
            for j1, j2 in ineq_con:
                if CT_NUM[sigma2[sigma1[j1]]] == CT_NUM[sigma2[sigma1[j2]]]:
                    fail = True
                    break
            if fail:
                continue

            dc_pass += 1
            composed = [sigma2[sigma1[j]] for j in range(N)]
            alphabets = recover_alphabets(composed, 7, res_groups)
            pt_str, n_decoded = decode_plaintext(composed, 7, alphabets)

            if dc_pass <= 10 or n_decoded > 50:
                print(f"  DC PASS #{dc_pass}: σ₁={all_orders[i1]} σ₂={all_orders[i2]}"
                      f" decoded={n_decoded}/97 PT={pt_str[:50]}")

            all_results.append({
                "period": 7,
                "model": "double_columnar",
                "order1": all_orders[i1],
                "order2": all_orders[i2],
                "n_decoded": n_decoded,
                "plaintext": pt_str,
            })

        if (i1 + 1) % 500 == 0:
            elapsed = time.time() - t0
            print(f"  σ₁ {i1+1}/5040  checked={dc_checked:,}  pass={dc_pass}"
                  f"  ({elapsed:.0f}s)", flush=True)

    print(f"\n  Double columnar (7,7): {dc_pass}/{dc_checked:,} pass mixed alphabet constraints")

    # =========================================================
    # SUMMARY
    # =========================================================
    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Time: {elapsed:.1f}s ({elapsed/60:.1f}min)")
    print(f"  Single columnar results: {len([r for r in all_results if 'model' not in r])}")
    print(f"  Double columnar results: {dc_pass}")

    # The key question: how many pass? If 0 → eliminated. If many → underdetermined.
    single_by_period = defaultdict(int)
    for r in all_results:
        if 'model' not in r:
            single_by_period[r['period']] += 1

    for p, count in sorted(single_by_period.items()):
        print(f"  Single columnar w=7 p={p}: {count} pass")
    print(f"  Double columnar (7,7) p=7: {dc_pass} pass")

    if dc_pass == 0 and all(c == 0 for c in single_by_period.values()):
        verdict = "ELIMINATED"
        print(f"\n  Mixed alphabet + width-7 columnar: FULLY ELIMINATED at all tested periods")
    elif dc_pass < 100:
        verdict = "INVESTIGATE"
        print(f"\n  Small number of solutions — worth investigating for English plaintext")
    else:
        verdict = "UNDERDETERMINED"
        print(f"\n  Too many solutions — constraint is too weak")

    print(f"\n  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_37_mixed_alphabet.json", "w") as f:
        json.dump({
            "experiment": "E-S-37",
            "description": "Mixed alphabet cipher + columnar transposition",
            "single_by_period": dict(single_by_period),
            "double_columnar_pass": dc_pass,
            "total_results": len(all_results),
            "verdict": verdict,
            "elapsed_seconds": round(elapsed, 1),
            "top_results": all_results[:30],
        }, f, indent=2)
    print(f"\n  Artifact: results/e_s_37_mixed_alphabet.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_37_mixed_alphabet.py")


if __name__ == "__main__":
    main()
