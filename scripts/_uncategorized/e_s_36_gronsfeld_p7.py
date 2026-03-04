#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-36: Exhaustive Gronsfeld Cipher at Period 7

Gronsfeld cipher = Vigenère restricted to single-digit keys (0-9).
"What's the point?" could mean digits, not letters.

Exhaustive search: all 10^7 = 10,000,000 possible 7-digit keys.
For each, check if the key produces consistent crib matches at period 7.

Also tests: Beaufort variant, and with all width-7 columnar transpositions.

Phase 1: Direct (identity transposition) — 10M keys, instant algebraic check
Phase 2: With width-7 transposition — 10M × 5040 orderings... too many.
         But: we can algebraically determine the required key for each ordering
         and check if it's all digits 0-9. This is 5040 orderings × O(1) check.

Output: results/e_s_36_gronsfeld_p7.json
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
PERIOD = 7


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


def main():
    print("=" * 60)
    print("E-S-36: Exhaustive Gronsfeld Cipher at Period 7")
    print("=" * 60)

    t0 = time.time()

    # Group crib positions by residue mod 7
    residue_groups = defaultdict(list)
    for j in CRIB_POS:
        residue_groups[j % PERIOD].append(j)

    print(f"  Crib residue groups at period 7:")
    for r in range(PERIOD):
        group = residue_groups[r]
        print(f"    r={r}: positions {group}")

    # =========================================================
    # Phase 1: Algebraic determination for identity transposition
    # For identity σ, CT[j] = (PT[j] + key[j%7]) % 26 [Vig]
    # key[r] = (CT[j] - PT[j]) % 26 for any j with j%7 == r
    # =========================================================
    print(f"\n{'='*60}")
    print(f"Phase 1: Identity transposition — algebraic")
    print(f"{'='*60}")

    for variant, sign in [("vig", -1), ("beau", 1)]:
        key = [None] * PERIOD
        consistent = True
        for r in range(PERIOD):
            vals = set()
            for j in residue_groups[r]:
                k_val = (CT_NUM[j] + sign * CRIB_PT[j]) % MOD
                vals.add(k_val)
            if len(vals) != 1:
                consistent = False
                print(f"  {variant}: residue {r} inconsistent: {vals}")
                break
            key[r] = vals.pop()

        if consistent:
            key_str = ''.join(chr(v + ord('A')) for v in key)
            is_gronsfeld = all(0 <= v <= 9 for v in key)
            print(f"  {variant}: key = {key} = {key_str}  Gronsfeld: {is_gronsfeld}")
        else:
            print(f"  {variant}: NOT period-7 consistent (expected — known from prior work)")

    # =========================================================
    # Phase 2: Width-7 columnar + Gronsfeld
    # For each ordering σ, determine the required key at each residue
    # and check if ALL key values are 0-9 (Gronsfeld constraint)
    # =========================================================
    print(f"\n{'='*60}")
    print(f"Phase 2: Width-7 columnar + Gronsfeld key (0-9)")
    print(f"{'='*60}")

    gronsfeld_hits = []
    digit_range_hits = []  # Key values in range 0-N for various N

    n_orderings = 0
    n_consistent = 0

    for order_tuple in permutations(range(7)):
        order = list(order_tuple)
        sigma = columnar_perm(order, 7, N)
        n_orderings += 1

        for variant, sign in [("vig", -1), ("beau", 1)]:
            # Model A: CT[σ(j)] = (PT[j] + key[j%p]) % 26
            # key[r] = (CT[σ(j)] + sign*PT[j]) % 26 for j with j%7==r
            key = [None] * PERIOD
            consistent = True
            for r in range(PERIOD):
                vals = set()
                for j in residue_groups[r]:
                    k_val = (CT_NUM[sigma[j]] + sign * CRIB_PT[j]) % MOD
                    vals.add(k_val)
                if len(vals) != 1:
                    consistent = False
                    break
                key[r] = vals.pop()

            if consistent:
                n_consistent += 1
                is_gronsfeld = all(0 <= v <= 9 for v in key)
                max_key = max(key)

                if is_gronsfeld:
                    gronsfeld_hits.append({
                        "model": "A",
                        "variant": variant,
                        "order": order,
                        "key": key,
                    })
                    print(f"  *** GRONSFELD: {variant} A order={order} key={key}")

                if max_key <= 12:  # Extended digit range
                    digit_range_hits.append({
                        "model": "A",
                        "variant": variant,
                        "order": order,
                        "key": key,
                        "max_key": max_key,
                    })

            # Model B: CT[j] = (PT[σ⁻¹(j)] + key[j%p]) % 26
            # For crib pos j: key[σ(j)%p] = (CT[σ(j)] + sign*PT[j]) % 26
            key_b = [None] * PERIOD
            consistent_b = True
            sigma_residue_groups = defaultdict(list)
            for j in CRIB_POS:
                sigma_residue_groups[sigma[j] % PERIOD].append(j)

            for r in range(PERIOD):
                group = sigma_residue_groups[r]
                if not group:
                    continue  # Underdetermined, skip
                vals = set()
                for j in group:
                    k_val = (CT_NUM[sigma[j]] + sign * CRIB_PT[j]) % MOD
                    vals.add(k_val)
                if len(vals) != 1:
                    consistent_b = False
                    break
                key_b[r] = vals.pop()

            if consistent_b and all(v is not None for v in key_b):
                is_gronsfeld = all(0 <= v <= 9 for v in key_b)
                if is_gronsfeld:
                    gronsfeld_hits.append({
                        "model": "B",
                        "variant": variant,
                        "order": order,
                        "key": key_b,
                    })
                    print(f"  *** GRONSFELD: {variant} B order={order} key={key_b}")

    print(f"\n  Orderings: {n_orderings}")
    print(f"  Period-7 consistent (Model A): {n_consistent}")
    print(f"  Gronsfeld hits (0-9): {len(gronsfeld_hits)}")
    print(f"  Extended digit hits (0-12): {len(digit_range_hits)}")

    # =========================================================
    # Phase 3: Date-based digit keys
    # =========================================================
    print(f"\n{'='*60}")
    print(f"Phase 3: Date-specific Gronsfeld keys")
    print(f"{'='*60}")

    date_keys = {
        "1986198": [1, 9, 8, 6, 1, 9, 8],
        "1989198": [1, 9, 8, 9, 1, 9, 8],
        "1986119": [1, 9, 8, 6, 1, 1, 9],
        "8619891": [8, 6, 1, 9, 8, 9, 1],
        "6798531": [6, 7, 9, 8, 5, 3, 1],  # Kryptos coords truncated
        "3857657": [3, 8, 5, 7, 6, 5, 7],  # lat digits
        "7708440": [7, 7, 0, 8, 4, 4, 0],  # lon digits
        "4152637": [4, 1, 5, 2, 6, 3, 7],  # K3 transposition key
    }

    for name, key in date_keys.items():
        for variant, sign in [("vig", -1), ("beau", 1)]:
            # Apply key and check how many cribs match
            matches = 0
            for j in CRIB_POS:
                ct_val = CT_NUM[j]
                if variant == "vig":
                    pt_val = (ct_val - key[j % 7]) % MOD
                else:
                    pt_val = (key[j % 7] - ct_val) % MOD
                if pt_val == CRIB_PT[j]:
                    matches += 1
            if matches >= 8:
                print(f"  {name} {variant}: {matches}/24 matches")

    # =========================================================
    # Phase 4: Brute-force ALL Gronsfeld keys (identity transposition)
    # 10^7 = 10M keys, but we can use the algebraic approach:
    # The required key at period 7 is FIXED by the cribs (if consistent).
    # So either there's one key or zero. Already checked in Phase 1.
    # For non-identity transpositions, already checked in Phase 2.
    #
    # Instead, test all digit keys 0-9 at periods 2-14
    # =========================================================
    print(f"\n{'='*60}")
    print(f"Phase 4: Gronsfeld at other periods (identity transposition)")
    print(f"{'='*60}")

    for p in range(2, 15):
        res_groups = defaultdict(list)
        for j in CRIB_POS:
            res_groups[j % p].append(j)

        for variant, sign in [("vig", -1), ("beau", 1)]:
            key = [None] * p
            consistent = True
            for r in range(p):
                if r not in res_groups:
                    continue
                vals = set()
                for j in res_groups[r]:
                    k_val = (CT_NUM[j] + sign * CRIB_PT[j]) % MOD
                    vals.add(k_val)
                if len(vals) != 1:
                    consistent = False
                    break
                key[r] = vals.pop()

            if consistent and all(v is not None for v in key):
                is_gronsfeld = all(0 <= v <= 9 for v in key)
                if is_gronsfeld:
                    print(f"  *** GRONSFELD p={p} {variant}: key={key}")

    # =========================================================
    # SUMMARY
    # =========================================================
    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Gronsfeld hits: {len(gronsfeld_hits)}")
    print(f"  Extended digit hits (max≤12): {len(digit_range_hits)}")

    if gronsfeld_hits:
        print(f"\n  Gronsfeld solutions found!")
        for h in gronsfeld_hits[:10]:
            print(f"    {h['model']} {h['variant']} order={h['order']} key={h['key']}")
        verdict = "SIGNAL"
    else:
        print(f"\n  No Gronsfeld solutions. ELIMINATED at period 7 for all width-7 orderings.")
        verdict = "NOISE"

    if digit_range_hits:
        print(f"\n  Extended digit range (max≤12) solutions:")
        for h in digit_range_hits[:20]:
            print(f"    {h['model']} {h['variant']} order={h['order']} key={h['key']}")

    print(f"\n  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_36_gronsfeld_p7.json", "w") as f:
        json.dump({
            "experiment": "E-S-36",
            "description": "Exhaustive Gronsfeld (digit-only key) at period 7",
            "n_orderings": n_orderings,
            "n_consistent_model_a": n_consistent,
            "gronsfeld_hits": gronsfeld_hits,
            "digit_range_hits": digit_range_hits[:50],
            "verdict": verdict,
            "elapsed_seconds": round(elapsed, 1),
        }, f, indent=2)
    print(f"\n  Artifact: results/e_s_36_gronsfeld_p7.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_36_gronsfeld_p7.py")


if __name__ == "__main__":
    main()
