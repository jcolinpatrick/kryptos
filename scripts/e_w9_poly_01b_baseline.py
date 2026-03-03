#!/usr/bin/env python3
"""E-W9-POLY-01b: Baseline — expected random score at period 10 with 24 cribs.

Quick Monte Carlo: for random permutations of CT, what score does the
same period-10 consistency check produce? This tells us whether 18/24
at period 10 is signal or noise.
"""
import random
import sys
from collections import defaultdict
from typing import Dict, List, Tuple

sys.path.insert(0, "src")
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, MOD

CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = [ALPH_IDX[CRIB_DICT[p]] for p in CRIB_POS]
CT_VALS = [ALPH_IDX[c] for c in CT]

PERIODS = list(range(3, 13))
N_TRIALS = 100_000


def score_random_perm(perm: List[int]) -> Tuple[int, int, str]:
    """Score a random permutation the same way as the main experiment."""
    inter_at_cribs = [CT_VALS[perm[p]] for p in CRIB_POS]

    best_score = 0
    best_period = 0
    best_variant = ""

    for variant_name, sign_fn in [
        ("vig", lambda ct_v, pt_v: (ct_v - pt_v) % MOD),
        ("beau", lambda ct_v, pt_v: (ct_v + pt_v) % MOD),
        ("varbeau", lambda ct_v, pt_v: (pt_v - ct_v) % MOD),
    ]:
        keys = [sign_fn(inter_at_cribs[i], CRIB_PT[i]) for i in range(N_CRIBS)]

        for period in PERIODS:
            residue_groups: Dict[int, List[int]] = defaultdict(list)
            for i, p in enumerate(CRIB_POS):
                residue_groups[p % period].append(i)

            consistent = 0
            for residue, indices in residue_groups.items():
                if len(indices) <= 1:
                    consistent += len(indices)
                    continue
                key_counts: Dict[int, int] = defaultdict(int)
                for idx in indices:
                    key_counts[keys[idx]] += 1
                consistent += max(key_counts.values())

            if consistent > best_score:
                best_score = consistent
                best_period = period
                best_variant = variant_name

    return best_score, best_period, best_variant


def main():
    print("E-W9-POLY-01b: Baseline Monte Carlo")
    print(f"Trials: {N_TRIALS:,}")
    print(f"Periods: {PERIODS}")
    print()

    indices = list(range(CT_LEN))
    score_counts = defaultdict(int)
    max_seen = 0

    for trial in range(N_TRIALS):
        perm = indices[:]
        random.shuffle(perm)
        score, period, variant = score_random_perm(perm)
        score_counts[score] += 1
        if score > max_seen:
            max_seen = score
            if trial > 0:
                print(f"  New max at trial {trial}: {score}/24 (p={period}, {variant})")

        if (trial + 1) % 20000 == 0:
            print(f"  Progress: {trial+1:,}/{N_TRIALS:,}")

    print()
    print("Score distribution (best score per random permutation):")
    for s in sorted(score_counts.keys()):
        pct = 100 * score_counts[s] / N_TRIALS
        bar = "#" * int(pct)
        print(f"  {s:2d}/24: {score_counts[s]:6d} ({pct:5.1f}%) {bar}")

    print()
    mean = sum(s * c for s, c in score_counts.items()) / N_TRIALS
    print(f"Mean: {mean:.2f}/24")
    print(f"Max: {max_seen}/24")
    print()

    # P-value for 18/24
    at_or_above_18 = sum(c for s, c in score_counts.items() if s >= 18)
    print(f"P(score >= 18) = {at_or_above_18}/{N_TRIALS} = {at_or_above_18/N_TRIALS:.6f}")
    at_or_above_20 = sum(c for s, c in score_counts.items() if s >= 20)
    print(f"P(score >= 20) = {at_or_above_20}/{N_TRIALS} = {at_or_above_20/N_TRIALS:.6f}")


if __name__ == "__main__":
    main()
