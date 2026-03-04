#!/usr/bin/env python3
"""
Cipher: running key
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-34: Transposition-Optimized Running Key Fragment Analysis

For each columnar transposition ordering σ (widths 5-8), compute the running
key values at the 24 known crib positions under both Vigenère and Beaufort.

Under Model A (sub then trans): CT[σ(j)] = (PT[j] + key[j]) % 26
  key[j] = (CT[σ(j)] - PT[j]) % 26  [Vig]
  key[j] = (CT[σ(j)] + PT[j]) % 26  [Beau]

Key positions 21-33 and 63-73 are CONSECUTIVE in the running key text.
Score these fragments using:
  1. English quadgram statistics
  2. Dictionary word matching
  3. Frequency distribution chi-squared vs English

Then cross-reference top fragments against Carter book and other texts.

Output: results/e_s_34_key_fragment_analysis.json
"""

import json
import sys
import os
import time
import math
from itertools import permutations
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

ENE_RANGE = list(range(21, 34))  # 13 positions
BC_RANGE = list(range(63, 74))   # 11 positions

# English letter frequencies
ENG_FREQ = {
    0: 0.0817, 1: 0.0150, 2: 0.0278, 3: 0.0425, 4: 0.1270,
    5: 0.0223, 6: 0.0202, 7: 0.0609, 8: 0.0697, 9: 0.0015,
    10: 0.0077, 11: 0.0403, 12: 0.0241, 13: 0.0675, 14: 0.0751,
    15: 0.0193, 16: 0.0010, 17: 0.0599, 18: 0.0633, 19: 0.0906,
    20: 0.0276, 21: 0.0098, 22: 0.0236, 23: 0.0015, 24: 0.0197,
    25: 0.0007,
}


def load_quadgrams():
    """Load quadgram log-probabilities."""
    path = "data/english_quadgrams.json"
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "logp" in data:
        return data["logp"]
    return data


def quadgram_score(text_nums, logp):
    """Score a numeric sequence using quadgram log-probabilities."""
    if logp is None or len(text_nums) < 4:
        return -999.0
    score = 0.0
    floor = -10.0  # penalty for unseen quadgrams
    for i in range(len(text_nums) - 3):
        qg = ''.join(chr(text_nums[i+k] + ord('A')) for k in range(4))
        score += logp.get(qg, floor)
    return score


def chi_squared_english(nums):
    """Chi-squared distance from English letter frequencies."""
    n = len(nums)
    if n == 0:
        return 999.0
    counts = [0] * 26
    for v in nums:
        counts[v] += 1
    chi2 = 0.0
    for i in range(26):
        expected = ENG_FREQ[i] * n
        if expected > 0:
            chi2 += (counts[i] - expected) ** 2 / expected
    return chi2


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
    """Load Carter book text for cross-reference."""
    path = "reference/carter_vol1_extract.txt"
    if not os.path.exists(path):
        return None
    with open(path) as f:
        text = f.read().strip().upper()
    return [ord(c) - ord('A') for c in text if c.isalpha()]


def search_in_text(fragment, text_nums):
    """Search for exact 13-letter or 11-letter fragment in text. Return offsets."""
    flen = len(fragment)
    offsets = []
    for i in range(len(text_nums) - flen + 1):
        if text_nums[i:i+flen] == fragment:
            offsets.append(i)
    return offsets


def main():
    print("=" * 60)
    print("E-S-34: Transposition-Optimized Running Key Fragment Analysis")
    print("=" * 60)

    t0 = time.time()

    logp = load_quadgrams()
    if logp:
        print(f"  Quadgrams loaded: {len(logp)} entries")
    else:
        print(f"  WARNING: No quadgrams file found, using chi-squared only")

    carter = load_carter_text()
    if carter:
        print(f"  Carter text: {len(carter)} chars")

    # Also identity transposition baseline
    print(f"\nBaseline (identity transposition):")
    ene_key_vig = [(CT_NUM[j] - CRIB_PT[j]) % MOD for j in ENE_RANGE]
    bc_key_vig = [(CT_NUM[j] - CRIB_PT[j]) % MOD for j in BC_RANGE]
    ene_str = ''.join(chr(v + ord('A')) for v in ene_key_vig)
    bc_str = ''.join(chr(v + ord('A')) for v in bc_key_vig)
    ene_qg = quadgram_score(ene_key_vig, logp) if logp else 0
    bc_qg = quadgram_score(bc_key_vig, logp) if logp else 0
    print(f"  Vig ENE key: {ene_str}  qg={ene_qg:.1f}  chi²={chi_squared_english(ene_key_vig):.1f}")
    print(f"  Vig BC key:  {bc_str}  qg={bc_qg:.1f}  chi²={chi_squared_english(bc_key_vig):.1f}")

    ene_key_beau = [(CT_NUM[j] + CRIB_PT[j]) % MOD for j in ENE_RANGE]
    bc_key_beau = [(CT_NUM[j] + CRIB_PT[j]) % MOD for j in BC_RANGE]
    ene_str_b = ''.join(chr(v + ord('A')) for v in ene_key_beau)
    bc_str_b = ''.join(chr(v + ord('A')) for v in bc_key_beau)
    print(f"  Beau ENE key: {ene_str_b}")
    print(f"  Beau BC key:  {bc_str_b}")

    # Scan all widths
    all_candidates = []

    for width in [5, 6, 7, 8]:
        t_w = time.time()
        n_orderings = 0
        width_best_qg = -999

        for order_tuple in permutations(range(width)):
            order = list(order_tuple)
            sigma = columnar_perm(order, width, N)
            n_orderings += 1

            for variant, sign in [("vig", -1), ("beau", 1)]:
                # Compute key fragments
                ene_key = [(CT_NUM[sigma[j]] + sign * CRIB_PT[j]) % MOD for j in ENE_RANGE]
                bc_key = [(CT_NUM[sigma[j]] + sign * CRIB_PT[j]) % MOD for j in BC_RANGE]

                # Score
                ene_qg = quadgram_score(ene_key, logp) if logp else 0
                bc_qg = quadgram_score(bc_key, logp) if logp else 0
                combined_qg = ene_qg + bc_qg

                ene_chi2 = chi_squared_english(ene_key)
                bc_chi2 = chi_squared_english(bc_key)

                ene_str = ''.join(chr(v + ord('A')) for v in ene_key)
                bc_str = ''.join(chr(v + ord('A')) for v in bc_key)

                if combined_qg > width_best_qg:
                    width_best_qg = combined_qg

                all_candidates.append({
                    "width": width,
                    "order": order,
                    "variant": variant,
                    "ene_key": ene_str,
                    "bc_key": bc_str,
                    "ene_qg": round(ene_qg, 2),
                    "bc_qg": round(bc_qg, 2),
                    "combined_qg": round(combined_qg, 2),
                    "ene_chi2": round(ene_chi2, 1),
                    "bc_chi2": round(bc_chi2, 1),
                })

        t_w_elapsed = time.time() - t_w
        print(f"\n  Width {width}: {n_orderings} orderings, "
              f"best combined_qg={width_best_qg:.1f} ({t_w_elapsed:.1f}s)",
              flush=True)

    # Sort by combined quadgram score (higher = more English-like)
    all_candidates.sort(key=lambda c: -c['combined_qg'])

    print(f"\n{'='*60}")
    print(f"TOP 30 CANDIDATES (by combined quadgram score)")
    print(f"{'='*60}")
    for i, c in enumerate(all_candidates[:30]):
        print(f"  {i+1:3d}. w={c['width']} {c['variant']} order={c['order']}"
              f"  ENE={c['ene_key']} BC={c['bc_key']}"
              f"  qg={c['combined_qg']:.1f} chi²=({c['ene_chi2']:.0f},{c['bc_chi2']:.0f})")

    # Cross-reference top candidates against Carter text
    if carter:
        print(f"\n{'='*60}")
        print(f"CARTER BOOK CROSS-REFERENCE (top 100 candidates)")
        print(f"{'='*60}")
        n_carter_hits = 0
        for c in all_candidates[:100]:
            ene_nums = [ALPH_IDX[ch] for ch in c['ene_key']]
            bc_nums = [ALPH_IDX[ch] for ch in c['bc_key']]
            ene_offsets = search_in_text(ene_nums, carter)
            bc_offsets = search_in_text(bc_nums, carter)
            if ene_offsets or bc_offsets:
                n_carter_hits += 1
                print(f"  w={c['width']} {c['variant']} order={c['order']}"
                      f"  ENE_hits={len(ene_offsets)} BC_hits={len(bc_offsets)}")
                if ene_offsets:
                    for off in ene_offsets[:3]:
                        context = ''.join(chr(carter[i]+ord('A')) for i in range(max(0,off-5), min(len(carter),off+18)))
                        print(f"    ENE at {off}: ...{context}...")
                if bc_offsets:
                    for off in bc_offsets[:3]:
                        context = ''.join(chr(carter[i]+ord('A')) for i in range(max(0,off-5), min(len(carter),off+16)))
                        print(f"    BC at {off}: ...{context}...")

        if n_carter_hits == 0:
            print(f"  No Carter text matches for any top-100 candidate.")

    # Also check: which candidates have key fragments that match
    # at consistent offset in Carter (i.e., BC fragment at offset = ENE offset + 42)
    if carter:
        print(f"\n  Checking consistent offset (BC at ENE+42)...")
        consistent_hits = 0
        for c in all_candidates[:500]:
            ene_nums = [ALPH_IDX[ch] for ch in c['ene_key']]
            bc_nums = [ALPH_IDX[ch] for ch in c['bc_key']]
            ene_offsets = search_in_text(ene_nums, carter)
            for ene_off in ene_offsets:
                bc_off = ene_off + 42  # BC starts 42 positions after ENE in PT
                if bc_off + 11 <= len(carter):
                    if carter[bc_off:bc_off+11] == bc_nums:
                        consistent_hits += 1
                        context = ''.join(chr(carter[i]+ord('A'))
                                         for i in range(ene_off, min(len(carter), ene_off+55)))
                        print(f"  *** CONSISTENT HIT: w={c['width']} {c['variant']}"
                              f" order={c['order']} offset={ene_off}")
                        print(f"      Key text: {context}")

        if consistent_hits == 0:
            print(f"  No consistent Carter hits found.")

    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Total candidates: {len(all_candidates):,}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Best combined quadgram: {all_candidates[0]['combined_qg']:.1f}")
    print(f"  Best config: w={all_candidates[0]['width']} {all_candidates[0]['variant']}"
          f" order={all_candidates[0]['order']}")
    print(f"    ENE key: {all_candidates[0]['ene_key']}")
    print(f"    BC key:  {all_candidates[0]['bc_key']}")

    # Verdict
    # English 13-gram quadgram score: typical English ~-30, random ~-50
    best = all_candidates[0]['combined_qg']
    verdict = "SIGNAL" if best > -50 else "NOISE"
    print(f"\n  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_34_key_fragment_analysis.json", "w") as f:
        json.dump({
            "experiment": "E-S-34",
            "widths_tested": [5, 6, 7, 8],
            "total_candidates": len(all_candidates),
            "verdict": verdict,
            "elapsed_seconds": round(elapsed, 1),
            "top_30": all_candidates[:30],
        }, f, indent=2)
    print(f"\n  Artifact: results/e_s_34_key_fragment_analysis.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_34_key_fragment_analysis.py")


if __name__ == "__main__":
    main()
