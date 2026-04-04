#!/usr/bin/env python3 -u
"""
=================================================================
SANBORN ERROR — BEAUFORT SENSITIVITY TEST
=================================================================
Cipher:     Beaufort (period 1, period 7 KRYPTOS keyword)
Family:     campaigns
Status:     active
Keyspace:   2,425 mutations × (26 + 1) keys = ~67K decryptions
Last run:   never
Best score: --

HYPOTHESIS
----------
If exactly ONE ciphertext letter is wrong, does the score ceiling
for Beaufort decryption increase materially?

For each of 97×25=2,425 single-letter mutations:
  - Beaufort decrypt with all 26 single-letter keys (period 1)
  - Beaufort decrypt with KRYPTOS keyword (period 7)
  - Score via score_candidate()
=================================================================
"""

import sys
import os
import json
import time
from multiprocessing import Pool, cpu_count
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.text import text_to_nums

# ── Constants ─────────────────────────────────────────────────────

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
# Period-7 key: "KRYPTOS" as numeric values
KRYPTOS_KEY = text_to_nums("KRYPTOS")


def score_mutation(args):
    """Score a single CT mutation against Beaufort keys.
    Returns (mut_pos, orig_char, alt_char, best_score, best_method, best_pt_preview)."""
    mut_pos, orig_char, alt_char = args
    mut_ct = CT[:mut_pos] + alt_char + CT[mut_pos + 1:]

    best_score = 0
    best_method = ""
    best_pt = ""

    # Period-1 Beaufort: 26 single-letter keys
    for k_idx in range(26):
        key = [k_idx]
        pt = decrypt_text(mut_ct, key, CipherVariant.BEAUFORT)
        result = score_candidate(pt)
        s = result.crib_score
        if s > best_score:
            best_score = s
            best_method = f"beaufort_p1_key={ALPHA[k_idx]}"
            best_pt = pt[:30]

    # Period-7 Beaufort with key "KRYPTOS"
    pt = decrypt_text(mut_ct, KRYPTOS_KEY, CipherVariant.BEAUFORT)
    result = score_candidate(pt)
    s = result.crib_score
    if s > best_score:
        best_score = s
        best_method = "beaufort_p7_key=KRYPTOS"
        best_pt = pt[:30]

    return (mut_pos, orig_char, alt_char, best_score, best_method, best_pt)


def main():
    t0 = time.time()
    print("=" * 70)
    print("SANBORN ERROR — BEAUFORT SENSITIVITY TEST")
    print("=" * 70)
    print(f"CT ({CT_LEN} chars): {CT}")
    print(f"Mutations: {CT_LEN} positions x 25 alternatives = {CT_LEN * 25}")
    print(f"Keys per mutation: 26 (period-1) + 1 (KRYPTOS period-7) = 27")
    print(f"Total decryptions: {CT_LEN * 25 * 27}")

    # Baseline: score unmutated CT
    print("\n--- BASELINE (no mutation) ---")
    baseline_best = 0
    baseline_method = ""
    baseline_pt = ""
    for k_idx in range(26):
        key = [k_idx]
        pt = decrypt_text(CT, key, CipherVariant.BEAUFORT)
        result = score_candidate(pt)
        if result.crib_score > baseline_best:
            baseline_best = result.crib_score
            baseline_method = f"beaufort_p1_key={ALPHA[k_idx]}"
            baseline_pt = pt[:30]
    pt = decrypt_text(CT, KRYPTOS_KEY, CipherVariant.BEAUFORT)
    result = score_candidate(pt)
    if result.crib_score > baseline_best:
        baseline_best = result.crib_score
        baseline_method = "beaufort_p7_key=KRYPTOS"
        baseline_pt = pt[:30]
    print(f"  Best baseline score: {baseline_best}/24 ({baseline_method})")
    print(f"  PT preview: {baseline_pt}")

    # Build work items
    work = []
    for pos in range(CT_LEN):
        orig = CT[pos]
        for alt_idx in range(26):
            alt = ALPHA[alt_idx]
            if alt == orig:
                continue
            work.append((pos, orig, alt))

    n_workers = max(1, min(cpu_count() - 2, 26))
    print(f"\n--- RUNNING {len(work)} mutations on {n_workers} workers ---")
    sys.stdout.flush()

    with Pool(n_workers) as pool:
        results = pool.map(score_mutation, work, chunksize=50)

    elapsed = time.time() - t0

    # Analyze
    scores = [r[3] for r in results]
    score_dist = Counter(scores)

    # Sort by score descending
    results_sorted = sorted(results, key=lambda x: x[3], reverse=True)

    print(f"\n{'=' * 70}")
    print(f"RESULTS (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")

    # Q1: Any score > 15?
    above_15 = [r for r in results if r[3] > 15]
    print(f"\n  Mutations with score > 15/24: {len(above_15)}")
    if above_15:
        for r in sorted(above_15, key=lambda x: x[3], reverse=True)[:10]:
            print(f"    pos={r[0]:>2} {r[1]}->{r[2]} score={r[3]:>2}/24 {r[4]} PT={r[5]}")

    # Q2: Top 10 mutations
    print(f"\n  TOP 10 MUTATIONS BY SCORE:")
    for i, r in enumerate(results_sorted[:10]):
        print(f"    {i+1:>2}. pos={r[0]:>2} {r[1]}->{r[2]} score={r[3]:>2}/24 {r[4]} PT={r[5]}")

    # Q3: Score distribution
    print(f"\n  SCORE DISTRIBUTION (across {len(results)} mutations):")
    for score_val in sorted(score_dist.keys(), reverse=True):
        bar = "#" * min(score_dist[score_val], 60)
        print(f"    score={score_val:>2}: {score_dist[score_val]:>5} {bar}")

    # Summary statistics
    import statistics
    print(f"\n  Mean best score: {statistics.mean(scores):.2f}")
    print(f"  Median: {statistics.median(scores):.1f}")
    print(f"  Max: {max(scores)}")
    print(f"  Std dev: {statistics.stdev(scores):.2f}")

    # Verdict
    print(f"\n  VERDICT:")
    if max(scores) <= baseline_best + 2:
        print(f"  No mutation improves score materially over baseline ({baseline_best}/24).")
        print(f"  Single-letter CT error does NOT unlock simple Beaufort decryption.")
    elif max(scores) > 15:
        print(f"  WARNING: {len(above_15)} mutations score above 15 -- investigate!")
    else:
        print(f"  Marginal improvement (max {max(scores)} vs baseline {baseline_best}).")
        print(f"  Insufficient to suggest a single-letter error unlocks Beaufort.")

    # Save results
    output = {
        "experiment": "sanborn_error_beaufort_sensitivity",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_s": round(elapsed, 1),
        "baseline_score": baseline_best,
        "baseline_method": baseline_method,
        "n_mutations": len(work),
        "n_decryptions": len(work) * 27,
        "score_distribution": {str(k): v for k, v in sorted(score_dist.items())},
        "max_score": max(scores),
        "mean_score": round(statistics.mean(scores), 2),
        "top_10": [
            {
                "pos": r[0], "orig": r[1], "alt": r[2],
                "score": r[3], "method": r[4], "pt_preview": r[5]
            }
            for r in results_sorted[:10]
        ],
        "verdict": "NO_SIGNAL" if max(scores) <= 15 else "INVESTIGATE",
    }
    out_path = os.path.join(_ROOT, "results", "e_sanborn_error_beaufort_sensitivity.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved: {out_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
