#!/usr/bin/env python3
"""
E-S-38: KA-Alphabet Vigenère Tableau Key Analysis

K1-K3 use the KRYPTOS alphabet (KA): KRYPTOSABCDEFGHIJLMNQUVWXZ
If K4 also uses this tableau, the running key derivation changes.

Standard Vigenère:  k = (CT - PT) % 26   → key letter = chr(k + 'A')
KA Vigenère:        k = (KA⁻¹(CT) - KA⁻¹(PT)) % 26 → key letter = KA[k]

For each columnar ordering (widths 5-8), compute key fragments under BOTH
standard and KA tableau, score with quadgrams, and search in Carter text.

Also tests mixed models:
  - KA for substitution, standard for transposition
  - Standard for substitution, KA for position lookup
  - Beaufort through KA tableau

Output: results/e_s_38_ka_tableau.json
"""

import json
import sys
import os
import time
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

ENE_RANGE = list(range(21, 34))
BC_RANGE = list(range(63, 74))

# KA alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}
KA_NUM = [KA_IDX[c] for c in CT]  # CT in KA-index space
CRIB_PT_KA = {pos: KA_IDX[ch] for pos, ch in CRIB_DICT.items()}


def load_quadgrams():
    path = "data/english_quadgrams.json"
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    return data.get("logp", data)


def quadgram_score(text, logp):
    if logp is None or len(text) < 4:
        return -999.0
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += logp.get(qg, -10.0)
    return score


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


def load_carter_text():
    path = "reference/carter_vol1_extract.txt"
    if not os.path.exists(path):
        return None
    with open(path) as f:
        text = f.read().strip().upper()
    return [ord(c) - ord('A') for c in text if c.isalpha()]


def search_in_text(fragment_nums, text_nums):
    flen = len(fragment_nums)
    offsets = []
    for i in range(len(text_nums) - flen + 1):
        if text_nums[i:i+flen] == fragment_nums:
            offsets.append(i)
    return offsets


def main():
    print("=" * 60)
    print("E-S-38: KA-Alphabet Vigenère Tableau Key Analysis")
    print("=" * 60)
    print(f"  KA alphabet: {KA}")

    t0 = time.time()
    logp = load_quadgrams()
    carter = load_carter_text()
    if carter:
        print(f"  Carter text: {len(carter)} chars")

    # Models to test:
    # 1. Standard Vig: k = (CT[σ(j)] - PT[j]) % 26, key_letter = chr(k + 'A')
    # 2. Standard Beau: k = (CT[σ(j)] + PT[j]) % 26, key_letter = chr(k + 'A')
    # 3. KA Vig: k = (KA⁻¹(CT[σ(j)]) - KA⁻¹(PT[j])) % 26, key_letter = KA[k]
    # 4. KA Beau: k = (KA⁻¹(CT[σ(j)]) + KA⁻¹(PT[j])) % 26, key_letter = KA[k]
    # 5. Mixed: KA for CT, standard for PT (and vice versa)

    models = [
        ("std_vig",  lambda ct, pt: (ct - pt) % 26, lambda k: chr(k + ord('A'))),
        ("std_beau", lambda ct, pt: (ct + pt) % 26, lambda k: chr(k + ord('A'))),
        ("ka_vig",   lambda ct, pt: (KA_IDX[chr(ct + ord('A'))] - KA_IDX[chr(pt + ord('A'))]) % 26,
                     lambda k: KA[k]),
        ("ka_beau",  lambda ct, pt: (KA_IDX[chr(ct + ord('A'))] + KA_IDX[chr(pt + ord('A'))]) % 26,
                     lambda k: KA[k]),
        # Mixed models
        ("ka_ct_std_pt_vig", lambda ct, pt: (KA_IDX[chr(ct + ord('A'))] - pt) % 26,
                             lambda k: chr(k + ord('A'))),
        ("std_ct_ka_pt_vig", lambda ct, pt: (ct - KA_IDX[chr(pt + ord('A'))]) % 26,
                             lambda k: chr(k + ord('A'))),
    ]

    all_candidates = []

    for width in [7, 5, 6, 8]:
        n_orderings = 0
        for order_tuple in permutations(range(width)):
            order = list(order_tuple)
            sigma = columnar_perm(order, width, N)
            n_orderings += 1

            for model_name, key_func, letter_func in models:
                # Compute key fragments at ENE and BC positions
                try:
                    ene_keys = [key_func(CT_NUM[sigma[j]], CRIB_PT[j]) for j in ENE_RANGE]
                    bc_keys = [key_func(CT_NUM[sigma[j]], CRIB_PT[j]) for j in BC_RANGE]
                except (KeyError, IndexError):
                    continue

                ene_str = ''.join(letter_func(k) for k in ene_keys)
                bc_str = ''.join(letter_func(k) for k in bc_keys)

                ene_qg = quadgram_score(ene_str, logp)
                bc_qg = quadgram_score(bc_str, logp)
                combined_qg = ene_qg + bc_qg

                all_candidates.append({
                    "width": width,
                    "order": order,
                    "model": model_name,
                    "ene_key": ene_str,
                    "bc_key": bc_str,
                    "combined_qg": round(combined_qg, 2),
                })

        print(f"  Width {width}: {n_orderings} orderings × {len(models)} models"
              f" ({time.time()-t0:.1f}s)", flush=True)

    # Sort by combined quadgram score
    all_candidates.sort(key=lambda c: -c['combined_qg'])

    # Print top results
    print(f"\n{'='*60}")
    print(f"TOP 30 CANDIDATES (by combined quadgram score)")
    print(f"{'='*60}")
    for i, c in enumerate(all_candidates[:30]):
        print(f"  {i+1:3d}. w={c['width']} {c['model']:20s} order={c['order']}"
              f"  ENE={c['ene_key']} BC={c['bc_key']}"
              f"  qg={c['combined_qg']:.1f}")

    # Compare models: what's the best score for each model type?
    print(f"\n{'='*60}")
    print(f"BEST SCORE BY MODEL")
    print(f"{'='*60}")
    model_bests = {}
    for c in all_candidates:
        m = c['model']
        if m not in model_bests or c['combined_qg'] > model_bests[m]['combined_qg']:
            model_bests[m] = c
    for m, c in sorted(model_bests.items(), key=lambda x: -x[1]['combined_qg']):
        print(f"  {m:25s}: qg={c['combined_qg']:.1f}"
              f"  w={c['width']} order={c['order']}"
              f"  ENE={c['ene_key']} BC={c['bc_key']}")

    # Carter text cross-reference for top candidates
    if carter:
        print(f"\n{'='*60}")
        print(f"CARTER CROSS-REFERENCE (top 200)")
        print(f"{'='*60}")
        n_hits = 0
        for c in all_candidates[:200]:
            ene_nums = [ord(ch) - ord('A') for ch in c['ene_key']]
            bc_nums = [ord(ch) - ord('A') for ch in c['bc_key']]

            ene_offsets = search_in_text(ene_nums, carter)
            bc_offsets = search_in_text(bc_nums, carter)

            if ene_offsets or bc_offsets:
                n_hits += 1
                print(f"  {c['model']} w={c['width']} order={c['order']}"
                      f" ENE_hits={len(ene_offsets)} BC_hits={len(bc_offsets)}")

            # Consistent offset check (BC at ENE+42)
            for ene_off in ene_offsets:
                bc_off = ene_off + 42
                if bc_off + 11 <= len(carter):
                    if carter[bc_off:bc_off+11] == bc_nums:
                        print(f"  *** CONSISTENT: {c['model']} w={c['width']}"
                              f" order={c['order']} offset={ene_off}")
                        ctx = ''.join(chr(carter[i]+65)
                                     for i in range(ene_off, min(len(carter), ene_off+55)))
                        print(f"      Text: {ctx}")

        if n_hits == 0:
            print(f"  No Carter matches.")

    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Total candidates: {len(all_candidates):,}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Best overall qg: {all_candidates[0]['combined_qg']:.1f}")
    print(f"  Best model: {all_candidates[0]['model']}")

    # Is KA significantly better than standard?
    std_best = max(c['combined_qg'] for c in all_candidates if 'std' in c['model'])
    ka_best = max(c['combined_qg'] for c in all_candidates if 'ka' in c['model'])
    print(f"  Best standard: {std_best:.1f}")
    print(f"  Best KA: {ka_best:.1f}")
    print(f"  KA improvement: {ka_best - std_best:+.1f}")

    verdict = "SIGNAL" if all_candidates[0]['combined_qg'] > -50 else "NOISE"
    print(f"\n  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_38_ka_tableau.json", "w") as f:
        json.dump({
            "experiment": "E-S-38",
            "models_tested": [m[0] for m in models],
            "widths_tested": [5, 6, 7, 8],
            "total_candidates": len(all_candidates),
            "verdict": verdict,
            "std_best": std_best,
            "ka_best": ka_best,
            "elapsed_seconds": round(elapsed, 1),
            "top_30": all_candidates[:30],
            "model_bests": {k: v for k, v in model_bests.items()},
        }, f, indent=2)
    print(f"\n  Artifact: results/e_s_38_ka_tableau.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_38_ka_tableau.py")


if __name__ == "__main__":
    main()
