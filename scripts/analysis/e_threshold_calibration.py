#!/usr/bin/env python3
"""Calibrate crib-score thresholds against the null distribution.

AUDIT REMEDIATION (2026-04-01): The scoring thresholds (NOISE=6, STORE=10,
SIGNAL=18, BREAKTHROUGH=24) are practical heuristics. This script generates
the null distribution of crib scores under random 97-character text to
document what random performance actually looks like.

Metadata:
  id: e_threshold_calibration
  family: analysis/statistical
  status: active
  description: Null distribution of crib scores for threshold calibration
"""
import sys
import os

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

import random
from multiprocessing import Pool, cpu_count

from kryptos.kernel.constants import CT_LEN, CRIB_DICT
from kryptos.kernel.scoring.crib_score import score_cribs


def generate_random_text(length, rng):
    """Generate random uppercase A-Z text."""
    return "".join(chr(65 + rng.randint(0, 25)) for _ in range(length))


def trial_batch(args):
    """Run a batch of random-text scoring trials."""
    seed, n_trials = args
    rng = random.Random(seed)
    scores = []
    for _ in range(n_trials):
        text = generate_random_text(CT_LEN, rng)
        scores.append(score_cribs(text))
    return scores


def main():
    N_TRIALS = 2_000_000
    n_workers = max(1, cpu_count() - 2)
    trials_per_worker = N_TRIALS // n_workers

    print(f"Generating null distribution of crib scores")
    print(f"  Trials: {N_TRIALS:,}")
    print(f"  Text length: {CT_LEN}")
    print(f"  Crib positions: {len(CRIB_DICT)}")
    print(f"  Workers: {n_workers}")
    print()

    args = [(42 + i, trials_per_worker) for i in range(n_workers)]

    with Pool(n_workers) as pool:
        results = pool.map(trial_batch, args)

    all_scores = []
    for batch in results:
        all_scores.extend(batch)

    total = len(all_scores)

    # Compute distribution
    from collections import Counter
    dist = Counter(all_scores)
    max_score = max(dist.keys())

    print(f"{'='*60}")
    print(f"NULL DISTRIBUTION OF CRIB SCORES (random 97-char text)")
    print(f"{'='*60}")
    print(f"Total trials: {total:,}")
    print()

    # Basic stats
    mean_score = sum(all_scores) / total
    print(f"Mean score: {mean_score:.3f}")
    print(f"Max score observed: {max_score}")
    print()

    # Full distribution
    print(f"{'Score':>6} {'Count':>10} {'Fraction':>12} {'Cumulative':>12}")
    cumulative = 0
    for s in range(max_score + 1):
        c = dist.get(s, 0)
        cumulative += c
        print(f"{s:>6} {c:>10,} {c/total:>12.6f} {cumulative/total:>12.6f}")

    # Threshold analysis
    print(f"\n{'='*60}")
    print(f"THRESHOLD ANALYSIS")
    print(f"{'='*60}")
    thresholds = [
        ("NOISE_FLOOR (6)", 6),
        ("STORE_THRESHOLD (10)", 10),
        ("SIGNAL_THRESHOLD (18)", 18),
        ("BREAKTHROUGH (24)", 24),
    ]
    for name, thresh in thresholds:
        above = sum(1 for s in all_scores if s >= thresh)
        print(f"  {name}: P(score >= {thresh}) = {above/total:.2e} ({above:,}/{total:,})")

    # Percentiles
    sorted_scores = sorted(all_scores)
    percentiles = [50, 90, 95, 99, 99.9, 99.99, 99.999]
    print(f"\nPercentiles:")
    for pct in percentiles:
        idx = int(pct / 100 * total)
        if idx >= total:
            idx = total - 1
        print(f"  {pct:>7.3f}th percentile: score = {sorted_scores[idx]}")

    print(f"\nExpected score per position: 1/26 = {1/26:.4f}")
    print(f"Expected total: 24 × 1/26 = {24/26:.3f}")
    print(f"Observed mean: {mean_score:.3f}")

    # Commentary
    print(f"\n{'='*60}")
    print(f"CALIBRATION ASSESSMENT")
    print(f"{'='*60}")
    p_noise = sum(1 for s in all_scores if s >= 6) / total
    p_store = sum(1 for s in all_scores if s >= 10) / total
    p_signal = sum(1 for s in all_scores if s >= 18) / total
    print(f"NOISE_FLOOR=6: {p_noise:.2e} of random texts score ≥6")
    print(f"STORE_THRESHOLD=10: {p_store:.2e} of random texts score ≥10")
    print(f"SIGNAL_THRESHOLD=18: {p_signal:.2e} of random texts score ≥18")
    print(f"BREAKTHROUGH=24: effectively 0 (P ≈ (1/26)^24 ≈ 2.7e-34)")
    print()
    print(f"Note: These are for RANDOM text with NO cipher model. Under a periodic")
    print(f"key model, expected scores are HIGHER (see methodology page period table).")


if __name__ == "__main__":
    main()
