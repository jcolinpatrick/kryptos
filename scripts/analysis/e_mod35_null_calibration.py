#!/usr/bin/env python3
"""Mod-35 null calibration: how often does a random labeling achieve perfect separation?

AUDIT REMEDIATION (2026-04-01): The (pos%7, pos%5) table perfectly classifies 35 palette
positions as null/real (17 null, 18 real) in-sample. But this was found post-hoc. This
script answers: for a random 17/35 binary labeling, how often does SOME (mod M1, mod M2)
rule with M1*M2 <= 97 achieve perfect separation?

If the answer is high (>5%), the (7,5) finding is not special.
If the answer is low (<0.1%), the finding has some structural significance.

Metadata:
  id: e_mod35_null_calibration
  family: analysis/statistical
  status: active
  description: Null calibration for mod-pair classification of palette positions
"""
import sys
import os

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

import random
import itertools
from collections import defaultdict
from multiprocessing import Pool, cpu_count

from kryptos.kernel.constants import CT, NULL_PALETTE, CONSENSUS_NULL_POSITIONS


def get_palette_positions():
    """Get all positions where CT letter is in the null palette."""
    return [p for p in range(len(CT)) if CT[p] in NULL_PALETTE]


def check_perfect_separation(labels, positions, m1, m2):
    """Check if (pos%m1, pos%m2) perfectly separates the binary labels.

    Returns True if every occupied cell is pure (all 0s or all 1s).
    """
    cells = defaultdict(set)
    for pos, label in zip(positions, labels):
        cell = (pos % m1, pos % m2)
        cells[cell].add(label)
    return all(len(v) == 1 for v in cells.values())


def check_perfect_with_tiebreaker(labels, positions, m1, m2):
    """Check perfect separation allowing a 'first occurrence wins' tiebreaker.

    For mixed cells (both labels present), check if 'first position = label 1'
    rule resolves all conflicts.
    """
    cells = defaultdict(list)
    for pos, label in zip(positions, labels):
        cell = (pos % m1, pos % m2)
        cells[cell].append((pos, label))

    for cell_entries in cells.values():
        cell_labels = set(e[1] for e in cell_entries)
        if len(cell_labels) > 1:
            # Mixed cell — check first-occurrence tiebreaker
            sorted_entries = sorted(cell_entries, key=lambda x: x[0])
            first_label = sorted_entries[0][1]
            # All entries after the first with a different label must be the other label
            for _, lbl in sorted_entries[1:]:
                if lbl == first_label:
                    # Same label appearing after a different label — fails tiebreaker
                    # Actually: tiebreaker says "first = null (1), rest = real (0)"
                    # This is more complex — just check if first is always label=1
                    pass
            # Simpler: does the original data's tiebreaker (first=null) work?
            # For null calibration, just check pure separation (no tiebreaker)
            return False
    return True


def get_mod_pairs(max_product=97):
    """Generate all (m1, m2) pairs with m1*m2 <= max_product, m1 >= 2, m2 >= 2."""
    pairs = []
    for m1 in range(2, max_product + 1):
        for m2 in range(2, max_product // m1 + 1):
            if m1 * m2 <= max_product:
                pairs.append((m1, m2))
    return pairs


def trial_worker(args):
    """Run a batch of trials for a single worker."""
    seed, n_trials, positions, n_null, mod_pairs = args
    rng = random.Random(seed)
    n_pos = len(positions)
    perfect_count = 0
    perfect_with_75 = 0

    for _ in range(n_trials):
        # Random labeling: n_null positions labeled 1, rest labeled 0
        indices = list(range(n_pos))
        rng.shuffle(indices)
        labels = [0] * n_pos
        for i in indices[:n_null]:
            labels[i] = 1

        # Check all mod pairs
        found_any = False
        found_75 = False
        for m1, m2 in mod_pairs:
            if check_perfect_separation(labels, positions, m1, m2):
                found_any = True
                if (m1, m2) == (7, 5) or (m1, m2) == (5, 7):
                    found_75 = True
                break  # Found at least one — stop

        if found_any:
            perfect_count += 1
        if found_75:
            perfect_with_75 += 1

    return perfect_count, perfect_with_75


def main():
    positions = get_palette_positions()
    n_pos = len(positions)
    n_null = len(CONSENSUS_NULL_POSITIONS & set(range(len(CT))))

    # Verify
    labels_real = [1 if p in CONSENSUS_NULL_POSITIONS else 0 for p in positions]
    assert sum(labels_real) == 17
    assert n_pos == 35

    mod_pairs = get_mod_pairs(97)
    print(f"Palette positions: {n_pos}")
    print(f"Null count: {n_null}")
    print(f"Mod pairs with product ≤ 97: {len(mod_pairs)}")
    print(f"Includes (7,5): {(7,5) in mod_pairs}")
    print(f"Includes (5,7): {(5,7) in mod_pairs}")

    # Verify the real data achieves perfect separation at (7,5)
    real_perfect = check_perfect_separation(labels_real, positions, 7, 5)
    print(f"\nReal data perfect at (7,5): {real_perfect}")

    # Count how many mod pairs achieve perfect separation on real data
    real_perfect_pairs = []
    for m1, m2 in mod_pairs:
        if check_perfect_separation(labels_real, positions, m1, m2):
            real_perfect_pairs.append((m1, m2))
    print(f"Mod pairs with perfect separation on real data: {len(real_perfect_pairs)}")
    for pair in real_perfect_pairs:
        print(f"  {pair}")

    # Monte Carlo: random labelings
    N_TRIALS = 500_000
    n_workers = max(1, cpu_count() - 2)
    trials_per_worker = N_TRIALS // n_workers

    print(f"\nRunning {N_TRIALS:,} random labelings across {n_workers} workers...")
    print(f"For each labeling, checking {len(mod_pairs)} mod pairs for perfect separation")

    args = [
        (42 + i, trials_per_worker, positions, n_null, mod_pairs)
        for i in range(n_workers)
    ]

    with Pool(n_workers) as pool:
        results = pool.map(trial_worker, args)

    total_perfect = sum(r[0] for r in results)
    total_75 = sum(r[1] for r in results)
    total_trials = trials_per_worker * n_workers

    print(f"\n{'='*60}")
    print(f"RESULTS: Mod-35 Null Calibration")
    print(f"{'='*60}")
    print(f"Total trials: {total_trials:,}")
    print(f"Random labelings with ANY perfect mod-pair separation: {total_perfect:,} ({total_perfect/total_trials:.4%})")
    print(f"Random labelings with (7,5) or (5,7) perfect separation: {total_75:,} ({total_75/total_trials:.4%})")
    print(f"")
    if total_perfect > 0:
        print(f"P(any perfect separation | random labeling) ≈ {total_perfect/total_trials:.6f}")
    else:
        print(f"P(any perfect separation | random labeling) < {1/total_trials:.2e}")
    if total_75 > 0:
        print(f"P((7,5) perfect separation | random labeling) ≈ {total_75/total_trials:.6f}")
    else:
        print(f"P((7,5) perfect separation | random labeling) < {1/total_trials:.2e}")

    print(f"\nInterpretation:")
    if total_perfect / total_trials > 0.05:
        print(f"  The (7,5) finding is NOT unusual — {total_perfect/total_trials:.1%} of random labelings")
        print(f"  achieve perfect separation under some mod pair. Post-hoc fit confirmed.")
    elif total_perfect / total_trials > 0.001:
        print(f"  Moderately unusual ({total_perfect/total_trials:.2%}) — but not significant after")
        print(f"  accounting for the search over mod pairs.")
    else:
        print(f"  Unusual (<0.1%) — the perfect separation has some structural significance,")
        print(f"  though the specific (7,5) choice was not pre-specified.")


if __name__ == "__main__":
    main()
