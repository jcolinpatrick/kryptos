#!/usr/bin/env python3
"""Profile actual ngram_per_char distribution of TABP decryptions.

Answers: if we removed the NGRAM_PREFILTER, what does the score
distribution look like? Is the prefilter losing signal, or are all
TABP decryptions genuinely noise-floor?

Runs a small sample of (T, variant, key) combinations at period 26
(the only period with non-zero Bean INEQ survivors) and reports the
score histogram.
"""
from __future__ import annotations

import json
import os
import sys
from itertools import product

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    ALPH_IDX, CRIB_DICT, CRIB_POSITIONS, CT, CT_LEN, MOD,
)
from kryptos.kernel.constraints.bean import rederive_bean_for_transposition
from kryptos.kernel.scoring.ngram import get_default_scorer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from f_tabp_transposition_outer_v1 import (
    enumerate_all_transpositions, _compute_implied_keys, _decrypt_tabp,
    VARIANTS,
)


def profile_scores(max_ts: int = 50, max_enum_per_t: int = 2000):
    scorer = get_default_scorer()
    all_ts = enumerate_all_transpositions()
    print(f"Profiling ngram distribution — sampling up to {max_ts} Ts "
          f"with Bean-passing period 26")

    # K4 reference points
    k4_score = scorer.score_per_char(CT)
    print(f"Reference: K4 raw CT ngram_per_char = {k4_score:.4f}")
    import random
    random.seed(42)
    rand_text = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(97))
    rand_score = scorer.score_per_char(rand_text)
    print(f"Reference: random 97-char  ngram_per_char = {rand_score:.4f}")
    print(f"Reference: English prose target          ≈ -4.96\n")

    non_crib = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]

    scores_full = []
    scores_noncrib = []
    ts_used = 0
    total_enums = 0

    for label, pt_to_ct in all_ts:
        if ts_used >= max_ts:
            break
        try:
            _eq, ineq = rederive_bean_for_transposition(pt_to_ct)
        except Exception:
            continue

        period = 26
        # Bean INEQ check
        if any((a % period) == (b % period) for a, b in ineq):
            continue

        ts_used += 1

        for variant in VARIANTS:
            implied = _compute_implied_keys(pt_to_ct, variant)
            residue_values = {}
            consistent = True
            for pos, val in implied.items():
                r = pos % period
                ex = residue_values.get(r)
                if ex is None:
                    residue_values[r] = val
                elif ex != val:
                    consistent = False
                    break
            if not consistent:
                continue

            missing = [r for r in range(period) if r not in residue_values]
            if len(missing) > 3:
                continue

            # Limit enumeration per (T, variant) to keep sample manageable
            enum_cap = max_enum_per_t
            count = 0
            if missing:
                for vals in product(range(MOD), repeat=len(missing)):
                    if count >= enum_cap:
                        break
                    kv = dict(residue_values)
                    for r, v in zip(missing, vals):
                        kv[r] = v
                    keystream = [kv[i % period] for i in range(CT_LEN)]
                    pt = _decrypt_tabp(pt_to_ct, variant, keystream)
                    scores_full.append(scorer.score_per_char(pt))
                    nc = "".join(pt[i] for i in non_crib)
                    scores_noncrib.append(scorer.score_per_char(nc))
                    count += 1
                    total_enums += 1
            else:
                keystream = [residue_values[i % period] for i in range(CT_LEN)]
                pt = _decrypt_tabp(pt_to_ct, variant, keystream)
                scores_full.append(scorer.score_per_char(pt))
                nc = "".join(pt[i] for i in non_crib)
                scores_noncrib.append(scorer.score_per_char(nc))
                total_enums += 1

    print(f"Ts used: {ts_used}, total decryptions scored: {total_enums}\n")

    if not scores_full:
        print("No scores produced.")
        return

    def hist(scores, label):
        scores = sorted(scores)
        n = len(scores)
        print(f"=== {label} (n={n}) ===")
        print(f"  min:    {min(scores):.4f}")
        print(f"  max:    {max(scores):.4f}")
        print(f"  median: {scores[n//2]:.4f}")
        print(f"  mean:   {sum(scores)/n:.4f}")
        # Bucket histogram
        buckets = {}
        for s in scores:
            b = round(s * 2) / 2  # 0.5 buckets
            buckets[b] = buckets.get(b, 0) + 1
        for b in sorted(buckets.keys()):
            bar = "#" * min(50, buckets[b] // max(1, n // 50))
            print(f"  {b:>6.1f}: {buckets[b]:>6}  {bar}")
        # Threshold counts
        print(f"  >= -6.0: {sum(1 for s in scores if s >= -6.0)}")
        print(f"  >= -5.8: {sum(1 for s in scores if s >= -5.8)}")
        print(f"  >= -5.5: {sum(1 for s in scores if s >= -5.5)}")
        print(f"  >= -5.0: {sum(1 for s in scores if s >= -5.0)}")
        print(f"  >= -4.8: {sum(1 for s in scores if s >= -4.8)}")
        print()

    hist(scores_full, "FULL 97-char plaintext ngram_per_char")
    hist(scores_noncrib, "NON-CRIB 73-char subset ngram_per_char")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--max-ts", type=int, default=30)
    p.add_argument("--max-enum", type=int, default=2000)
    args = p.parse_args()
    profile_scores(args.max_ts, args.max_enum)
