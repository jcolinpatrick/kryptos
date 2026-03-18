#!/usr/bin/env python3
"""
Attack 3 from the user request: Autokey feasibility after width-6 transposition.

The prior autokey impossibility proof was for col7-transposed text.
With WIDTH-6 transposition, crib positions in the transposed text are DIFFERENT.
Check whether autokey becomes feasible.

For each of 720 col6 permutations:
  - Map crib positions through inverse transposition
  - For primer lengths 1-20, check:
    - How many "chain constraints" exist (where both pos and pos-primer_len are crib positions)
    - How many of those constraints are SATISFIED
  - If ALL chain constraints satisfied for some primer length, test actual keywords.

Also: direct autokey on CT73 with all 78 single/double letter primers.
"""

import sys
import os
import json
import time
import itertools
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET
from kryptos.kernel.transforms.vigenere import CipherVariant, KEY_RECOVERY, DECRYPT_FN
from kryptos.kernel.transforms.transposition import columnar_perm, invert_perm
from kryptos.kernel.transforms.autokey import autokey_decrypt

# Setup
CT97 = CT
MASK_24 = [0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 39, 40, 52, 55, 58, 59, 74, 75, 78, 84, 85, 88, 94, 96]
MASK_SET = set(MASK_24)

ct73_chars = []
ct73_to_ct97 = {}
for i in range(97):
    if i not in MASK_SET:
        ct73_to_ct97[len(ct73_chars)] = i
        ct73_chars.append(CT97[i])
CT73 = ''.join(ct73_chars)

ENE_CT97 = list(range(21, 34))
BCL_CT97 = list(range(63, 74))
ENE_TEXT = "EASTNORTHEAST"
BCL_TEXT = "BERLINCLOCK"

ct97_to_ct73 = {}
for ct73_idx, ct97_idx in ct73_to_ct97.items():
    ct97_to_ct73[ct97_idx] = ct73_idx

ENE_CT73 = [ct97_to_ct73[p] for p in ENE_CT97]
BCL_CT73 = [ct97_to_ct73[p] for p in BCL_CT97]

CRIB_CT73 = {}
for i, pos in enumerate(ENE_CT73):
    CRIB_CT73[pos] = ENE_TEXT[i]
for i, pos in enumerate(BCL_CT73):
    CRIB_CT73[pos] = BCL_TEXT[i]

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


def apply_columnar_inverse(text, width, col_order):
    n = len(text)
    nrows = (n + width - 1) // width
    ncomplete = n - (nrows - 1) * width

    col_lengths = []
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        if col_idx < ncomplete:
            col_lengths.append(nrows)
        else:
            col_lengths.append(nrows - 1)

    columns_by_rank = {}
    pos = 0
    for rank in range(width):
        length = col_lengths[rank]
        columns_by_rank[rank] = text[pos:pos + length]
        pos += length

    columns_by_idx = {}
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        columns_by_idx[col_idx] = columns_by_rank[rank]

    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(columns_by_idx[col]):
                result.append(columns_by_idx[col][row])

    return ''.join(result)


def map_cribs_through_transposition(crib_dict, width, col_order, text_len):
    perm = columnar_perm(width, col_order, text_len)
    inv = invert_perm(perm)
    mapped_cribs = {}
    for pos, ch in crib_dict.items():
        if pos < text_len:
            mapped_cribs[inv[pos]] = ch
    return mapped_cribs


def check_pt_autokey(ct_text, crib_dict, primer_len, variant_str):
    """Check PT-autokey feasibility.

    PT-autokey: key[i] = primer[i] for i < L, key[i] = PT[i-L] for i >= L

    For crib position p with p >= L:
      key[p] = PT[p-L]
      If p-L is also a crib position: we know both PT[p] and key[p]=PT[p-L]
      Recover: from CT[p] and key[p]=PT[p-L], compute PT[p]
      Check: does computed PT[p] match the crib?

    For crib position p with p < L:
      key[p] = primer[p] (unknown)
      Each gives one equation for primer[p]
      If multiple cribs have the same p: they must agree on primer[p]
    """
    # Identify chain constraints
    chain_pairs = []  # (pos, key_source_pos)
    for pos in crib_dict:
        key_src = pos - primer_len
        if key_src >= 0 and key_src in crib_dict:
            chain_pairs.append((pos, key_src))

    # Check each chain constraint
    n_ok = 0
    n_fail = 0
    for pos, key_src in chain_pairs:
        ct_val = ord(ct_text[pos]) - 65
        key_val = ord(crib_dict[key_src]) - 65  # PT[key_src] = crib

        if variant_str == "vigenere":
            pt_computed = (ct_val - key_val) % 26
        elif variant_str == "beaufort":
            pt_computed = (key_val - ct_val) % 26
        elif variant_str == "var_beaufort":
            pt_computed = (ct_val + key_val) % 26

        pt_expected = ord(crib_dict[pos]) - 65

        if pt_computed == pt_expected:
            n_ok += 1
        else:
            n_fail += 1

    # Check primer constraints
    primer_slots = defaultdict(set)
    for pos in crib_dict:
        if pos < primer_len:
            ct_val = ord(ct_text[pos]) - 65
            pt_val = ord(crib_dict[pos]) - 65

            if variant_str == "vigenere":
                k = (ct_val - pt_val) % 26
            elif variant_str == "beaufort":
                k = (ct_val + pt_val) % 26
            elif variant_str == "var_beaufort":
                k = (pt_val - ct_val) % 26

            primer_slots[pos].add(k)

    primer_conflicts = sum(1 for s in primer_slots.values() if len(s) > 1)

    return {
        'n_chain_ok': n_ok,
        'n_chain_fail': n_fail,
        'n_chain_total': n_ok + n_fail,
        'primer_conflicts': primer_conflicts,
        'primer_constrained': len(primer_slots),
        'is_feasible': n_fail == 0 and primer_conflicts == 0,
    }


def check_ct_autokey(ct_text, crib_dict, primer_len, variant_str):
    """Check CT-autokey feasibility.

    CT-autokey: key[i] = primer[i] for i < L, key[i] = CT[i-L] for i >= L

    The key at any position >= L is KNOWN (from the ciphertext alone).
    So for crib position p >= L: key[p] = CT[p-L], and we can directly
    verify: decrypt(CT[p], key[p]) == crib[p].
    """
    n_ok = 0
    n_fail = 0
    n_primer = 0

    for pos, pt_ch in crib_dict.items():
        if pos >= primer_len:
            ct_val = ord(ct_text[pos]) - 65
            key_val = ord(ct_text[pos - primer_len]) - 65

            if variant_str == "vigenere":
                pt_computed = (ct_val - key_val) % 26
            elif variant_str == "beaufort":
                pt_computed = (key_val - ct_val) % 26
            elif variant_str == "var_beaufort":
                pt_computed = (ct_val + key_val) % 26

            pt_expected = ord(pt_ch) - 65

            if pt_computed == pt_expected:
                n_ok += 1
            else:
                n_fail += 1
        else:
            n_primer += 1

    return {
        'n_ok': n_ok,
        'n_fail': n_fail,
        'n_total': n_ok + n_fail,
        'n_primer': n_primer,
        'is_feasible': n_fail == 0,
    }


def main():
    start_time = time.time()
    print(f"Autokey Feasibility after Width-6 Transposition")
    print(f"Started: {datetime.now().isoformat()}")
    print(f"CT73 = {CT73}")
    print()

    variants = ["vigenere", "beaufort", "var_beaufort"]

    # ============================================================
    # Part 1: Direct autokey on CT73 (no transposition)
    # ============================================================
    print("=" * 70)
    print("PART 1: Direct PT-autokey on CT73")
    print("=" * 70)

    for var in variants:
        print(f"\n  {var}:")
        for primer_len in range(1, 25):
            result = check_pt_autokey(CT73, CRIB_CT73, primer_len, var)
            if result['is_feasible'] and result['n_chain_total'] >= 3:
                print(f"    L={primer_len}: FEASIBLE! chains={result['n_chain_ok']}/{result['n_chain_total']}, "
                      f"primer_constrained={result['primer_constrained']}")
            elif result['n_chain_total'] > 0:
                pct = result['n_chain_ok'] / result['n_chain_total'] * 100 if result['n_chain_total'] > 0 else 0
                if primer_len <= 13 or result['n_chain_ok'] > result['n_chain_total'] * 0.8:
                    print(f"    L={primer_len}: {result['n_chain_ok']}/{result['n_chain_total']} chains OK ({pct:.0f}%), "
                          f"primer_conflicts={result['primer_conflicts']}")

    print(f"\n  Direct CT-autokey on CT73:")
    for var in variants:
        print(f"\n  {var}:")
        for primer_len in range(1, 25):
            result = check_ct_autokey(CT73, CRIB_CT73, primer_len, var)
            if result['is_feasible'] and result['n_total'] >= 3:
                print(f"    L={primer_len}: FEASIBLE! ok={result['n_ok']}/{result['n_total']}")
            elif result['n_total'] > 0 and result['n_ok'] > result['n_total'] * 0.7:
                print(f"    L={primer_len}: {result['n_ok']}/{result['n_total']} OK")

    # ============================================================
    # Part 2: Col6 + PT-autokey
    # ============================================================
    print("\n" + "=" * 70)
    print("PART 2: Col6 transposition + PT-autokey (all 720 perms)")
    print("=" * 70)

    all_perms = list(itertools.permutations(range(6)))
    feasible_count = 0
    best_chain_score = 0
    all_hits = []

    for perm_tuple in all_perms:
        col_order = list(perm_tuple)
        ct_int = apply_columnar_inverse(CT73, 6, col_order)
        mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, col_order, 73)

        for var in variants:
            for primer_len in range(1, 25):
                result = check_pt_autokey(ct_int, mapped_cribs, primer_len, var)

                if result['is_feasible'] and result['n_chain_total'] >= 5:
                    feasible_count += 1
                    all_hits.append((
                        result['n_chain_ok'],
                        perm_tuple,
                        var,
                        primer_len,
                        result
                    ))

                if result['n_chain_ok'] + (result['primer_constrained'] - result['primer_conflicts']) > best_chain_score:
                    total_ok = result['n_chain_ok'] + result['primer_constrained'] - result['primer_conflicts']
                    best_chain_score = total_ok

    print(f"\n  Feasible (all chain constraints satisfied, >= 5 chains): {feasible_count}")

    all_hits.sort(key=lambda x: x[0], reverse=True)
    if all_hits:
        print(f"  Top feasible hits:")
        for chain_ok, perm, var, primer_len, result in all_hits[:20]:
            print(f"    chains={chain_ok}, perm={perm}, {var}, L={primer_len}")
    else:
        print("  NO FEASIBLE CONFIGURATIONS FOUND")

    print(f"\n  Best total OK (chains + primer): {best_chain_score}")

    # ============================================================
    # Part 3: Col6 + CT-autokey
    # ============================================================
    print("\n" + "=" * 70)
    print("PART 3: Col6 transposition + CT-autokey (all 720 perms)")
    print("=" * 70)

    feasible_ct = 0
    ct_hits = []
    best_ct_ok = 0

    for perm_tuple in all_perms:
        col_order = list(perm_tuple)
        ct_int = apply_columnar_inverse(CT73, 6, col_order)
        mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, col_order, 73)

        for var in variants:
            for primer_len in range(1, 25):
                result = check_ct_autokey(ct_int, mapped_cribs, primer_len, var)

                if result['n_ok'] > best_ct_ok:
                    best_ct_ok = result['n_ok']

                if result['is_feasible'] and result['n_total'] >= 5:
                    feasible_ct += 1
                    ct_hits.append((
                        result['n_ok'],
                        perm_tuple,
                        var,
                        primer_len,
                        result
                    ))

    print(f"\n  Feasible (all verifiable positions OK, >= 5 positions): {feasible_ct}")
    print(f"  Best n_ok: {best_ct_ok}")

    ct_hits.sort(key=lambda x: x[0], reverse=True)
    if ct_hits:
        print(f"  Top feasible hits:")
        for n_ok, perm, var, primer_len, result in ct_hits[:20]:
            print(f"    ok={n_ok}/{result['n_total']}, perm={perm}, {var}, L={primer_len}")

            # Try actual keywords
            keywords = ["DEFECTOR", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "SEVEN", "SHADOW"]
            ct_int = apply_columnar_inverse(CT73, 6, list(perm))
            mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, list(perm), 73)

            for kw in keywords:
                if len(kw) >= primer_len:
                    primer = kw[:primer_len]
                    pt = autokey_decrypt(ct_int, primer, var)
                    crib_matches = sum(1 for p, ch in mapped_cribs.items() if p < len(pt) and pt[p] == ch)
                    if crib_matches >= 10:
                        print(f"      {primer}: {crib_matches}/24 crib matches")
                        print(f"      PT: {pt[:60]}")
    else:
        print("  NO FEASIBLE CONFIGURATIONS FOUND")

    # ============================================================
    # Part 4: Keyword autokey decrypt with crib scoring
    # ============================================================
    print("\n" + "=" * 70)
    print("PART 4: Keyword autokey decrypt scoring (col6 + keywords)")
    print("=" * 70)

    keywords = [
        "DEFECTOR", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN",
        "KOMPASS", "COLOPHON", "SHADOW", "SEVEN", "EAST",
        "BERLINCLOCK", "EASTNORTHEAST",
    ]

    best_overall = 0
    best_desc = ""

    for perm_tuple in all_perms:
        ct_int = apply_columnar_inverse(CT73, 6, list(perm_tuple))
        mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, list(perm_tuple), 73)

        for var in variants:
            for kw in keywords:
                pt = autokey_decrypt(ct_int, kw, var)
                crib_matches = sum(1 for p, ch in mapped_cribs.items() if p < len(pt) and pt[p] == ch)

                if crib_matches > best_overall:
                    best_overall = crib_matches
                    best_desc = f"perm={perm_tuple}, {var}, primer={kw}: {crib_matches}/24"

                if crib_matches >= 10:
                    print(f"  {crib_matches}/24: perm={perm_tuple}, {var}, primer={kw}")
                    print(f"    PT: {pt[:60]}")

    print(f"\n  Best overall: {best_desc}")

    elapsed = time.time() - start_time
    print(f"\nTotal elapsed: {elapsed:.1f}s")

    # Save
    results_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'f_period6_autokey_feasibility_v1.json')
    output = {
        'timestamp': datetime.now().isoformat(),
        'elapsed_seconds': elapsed,
        'ct73': CT73,
        'best_keyword_autokey': best_desc,
        'pt_autokey_feasible': feasible_count,
        'ct_autokey_feasible': feasible_ct,
    }
    with open(results_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"Results saved to: {results_path}")


if __name__ == '__main__':
    main()
