#!/usr/bin/env python3
"""
Cipher: statistical_audit
Family: statistical
Status: active
Keyspace: 50M Monte Carlo trials
Last run: never
Best score: N/A (diagnostic, not attack)

Joint null simulation for Claims 1 + 2 (palette restriction + keystream enrichment).

Replaces the INVALID Fisher combination (p=4.2e-6) with a proper joint null.
Two null models tested:

  Model A (position-shuffle): Fix CT. Randomly choose 17 of 73 non-crib positions
           as "nulls." Compute both statistics. This tests whether the specific
           null positions are special.

  Model B (letter-shuffle):   Randomly permute all 97 CT letters (keeping positions
           fixed). This creates new keystream values AND new null letters. Requires
           re-deriving the palette from the shuffled null letters. Tests whether
           the CT letter arrangement is special.

The observed statistics:
  - Claim 1: 17 consensus null positions use only 7 distinct letters (from PALETTE)
  - Claim 2: 13/24 Beaufort keystream values at crib positions are PALETTE members

For Fisher to be valid, these would need to be independent. They are not (both
are deterministic functions of the same 97-char CT). This script computes the
TRUE joint probability under each null model.

Target: 50M trials for Model A (fast), 50M for Model B (slightly slower).
At p~5e-7, expect ~25 hits in 50M trials (Poisson, 95% CI: 16-36).

Usage:
    PYTHONPATH=src python3 -u scripts/statistical/e_joint_null_simulation.py

Output:
    results/e_joint_null_simulation.json

Author: KryptosBot (statistical-review follow-up)
"""

import sys
import os
import json
import random
import time
import math
from collections import Counter
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS, ALPH_IDX, MOD

# ── Constants ──────────────────────────────────────────────────────────────

PALETTE = frozenset("BGIKOWZ")
PALETTE_SIZE = 7

# 17 consensus null positions
CONSENSUS_NULLS = frozenset([0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85])
assert len(CONSENSUS_NULLS) == 17

# Crib positions and plaintext
CRIB_POS = sorted(CRIB_POSITIONS)
CRIB_SET = frozenset(CRIB_POS)
assert len(CRIB_POS) == 24

# Non-crib positions (pool for null selection)
NON_CRIB_POS = [p for p in range(CT_LEN) if p not in CRIB_SET]
assert len(NON_CRIB_POS) == 73

# Known plaintext at crib positions
ENE = "EASTNORTHEAST"
BCL = "BERLINCLOCK"
PT_AT_CRIB = {}
for i, c in zip(range(21, 34), ENE):
    PT_AT_CRIB[i] = c
for i, c in zip(range(63, 74), BCL):
    PT_AT_CRIB[i] = c

# Pre-compute observed statistics
CT_LIST = list(CT)
CT_NUMS = [ALPH_IDX[c] for c in CT]
PT_NUMS_AT_CRIB = {p: ALPH_IDX[PT_AT_CRIB[p]] for p in CRIB_POS}

# Observed: null distinct letters
OBS_NULL_DISTINCT = len(set(CT[p] for p in CONSENSUS_NULLS))
assert OBS_NULL_DISTINCT == 7

# Observed: keystream palette count
OBS_KS_PALETTE = 0
for p in CRIB_POS:
    k_val = (CT_NUMS[p] + PT_NUMS_AT_CRIB[p]) % MOD
    k_letter = chr(k_val + ord("A"))
    if k_letter in PALETTE:
        OBS_KS_PALETTE += 1
assert OBS_KS_PALETTE == 13

# Pre-compute: which letters in the keystream are palette, as a function of CT value
# For each crib position p, k = (CT[p] + PT[p]) mod 26.
# PT[p] is fixed. So k is determined by CT[p].
# Pre-compute: for each crib position, the set of CT values that make k a palette letter.
PALETTE_NUMS = frozenset(ALPH_IDX[c] for c in PALETTE)

# For Model B: given a shuffled CT, compute both stats
# For speed, pre-compute the PT num at each crib position
CRIB_PT_NUMS = [PT_NUMS_AT_CRIB[p] for p in CRIB_POS]  # ordered by CRIB_POS

# ── Model A: Position-Shuffle ──────────────────────────────────────────────

def model_a_trial(rng):
    """
    Fix CT. Choose 17 random non-crib positions as "nulls."
    Return (null_distinct, ks_palette_count).

    The keystream is fixed (CT is fixed), so ks_palette_count = OBS_KS_PALETTE always.
    This model ONLY tests Claim 1 given Claim 2.
    """
    chosen = rng.sample(NON_CRIB_POS, 17)
    distinct = len(set(CT[p] for p in chosen))
    return distinct, OBS_KS_PALETTE


# ── Model B: Letter-Shuffle ───────────────────────────────────────────────

def model_b_trial(ct_nums_shuffled, non_crib_pos_list, crib_pos_list, crib_pt_nums):
    """
    Shuffle CT letter values. Compute both statistics on the shuffled CT.

    Claim 1: sample the shuffled CT at the FIXED 17 consensus null positions,
             count distinct letters. (We use fixed null positions because we're
             testing whether the CT arrangement makes these positions special.)

    Claim 2: compute Beaufort keystream at crib positions using shuffled CT,
             count palette hits.

    Returns (null_distinct, ks_palette_count).
    """
    # Claim 1: distinct letters at the 17 consensus null positions
    null_distinct = len(set(ct_nums_shuffled[p] for p in CONSENSUS_NULLS))

    # Claim 2: keystream palette count
    ks_pal = 0
    for idx, p in enumerate(crib_pos_list):
        k_val = (ct_nums_shuffled[p] + crib_pt_nums[idx]) % MOD
        if k_val in PALETTE_NUMS:
            ks_pal += 1

    return null_distinct, ks_pal


# ── Model C: Full Permutation (re-derive palette) ─────────────────────────

def model_c_trial(ct_nums_shuffled, crib_pos_list, crib_pt_nums):
    """
    Shuffle CT letters. Re-derive the palette from the null positions of the
    shuffled CT. Then test keystream enrichment against THAT palette.

    This is the auditor's "joint null" — tests whether the COMBINATION of
    restricted palette + keystream enrichment for that palette is surprising.

    Returns (null_distinct, ks_palette_from_derived_count).
    """
    # Derive palette from null positions of shuffled CT
    null_letter_set = set(ct_nums_shuffled[p] for p in CONSENSUS_NULLS)
    null_distinct = len(null_letter_set)

    # Keystream enrichment for the DERIVED palette
    ks_pal = 0
    for idx, p in enumerate(crib_pos_list):
        k_val = (ct_nums_shuffled[p] + crib_pt_nums[idx]) % MOD
        if k_val in null_letter_set:
            ks_pal += 1

    return null_distinct, ks_pal


# ── Main Simulation ──────────────────────────────────────────────────────

def run_simulation(n_trials_a, n_trials_b, n_trials_c, seed):
    rng = random.Random(seed)

    results = {
        "observed": {
            "null_distinct": OBS_NULL_DISTINCT,
            "ks_palette_count": OBS_KS_PALETTE,
            "palette": sorted(PALETTE),
            "null_positions": sorted(CONSENSUS_NULLS),
            "crib_positions": CRIB_POS,
        },
        "seed": seed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # ── Model A ──
    print(f"=== MODEL A: Position-Shuffle ({n_trials_a:,} trials) ===")
    print("  (Tests: P(null_distinct <= 7 | fixed CT, random null positions))")
    print("  Note: keystream is fixed under this model (CT unchanged)")
    t0 = time.time()
    a_hits = 0
    a_distinct_hist = Counter()
    report_interval = n_trials_a // 10

    for i in range(n_trials_a):
        nd, _ = model_a_trial(rng)
        a_distinct_hist[nd] += 1
        if nd <= OBS_NULL_DISTINCT:
            a_hits += 1
        if report_interval > 0 and (i + 1) % report_interval == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed
            p_est = a_hits / (i + 1)
            print(f"  {i+1:>12,} / {n_trials_a:,}  hits={a_hits}  p={p_est:.2e}  "
                  f"({rate:,.0f} trials/s)")

    a_elapsed = time.time() - t0
    a_pvalue = a_hits / n_trials_a
    # Wilson score 95% CI
    a_ci_lo, a_ci_hi = wilson_ci(a_hits, n_trials_a)

    print(f"\n  Model A result: {a_hits} / {n_trials_a:,} = p = {a_pvalue:.3e}")
    print(f"  95% CI: [{a_ci_lo:.3e}, {a_ci_hi:.3e}]")
    print(f"  Time: {a_elapsed:.1f}s\n")

    results["model_a"] = {
        "description": "Position-shuffle: random 17 of 73 non-crib positions as nulls, fixed CT",
        "n_trials": n_trials_a,
        "hits_distinct_le_7": a_hits,
        "p_value": a_pvalue,
        "ci_95_lo": a_ci_lo,
        "ci_95_hi": a_ci_hi,
        "elapsed_s": round(a_elapsed, 1),
        "distinct_histogram": {str(k): v for k, v in sorted(a_distinct_hist.items())},
        "note": "Keystream fixed (CT unchanged). Only tests Claim 1.",
    }

    # ── Model B ──
    print(f"=== MODEL B: Letter-Shuffle, Fixed Palette ({n_trials_b:,} trials) ===")
    print("  (Tests: P(null_distinct <= 7 AND ks_palette >= 13 | shuffled CT, fixed palette))")
    t0 = time.time()
    b_hits_joint = 0
    b_hits_c1_only = 0
    b_hits_c2_only = 0
    b_hits_either = 0
    ct_nums_work = list(CT_NUMS)  # working copy
    report_interval = n_trials_b // 10

    crib_pos_list = CRIB_POS
    crib_pt_nums = CRIB_PT_NUMS

    for i in range(n_trials_b):
        rng.shuffle(ct_nums_work)
        nd, kp = model_b_trial(ct_nums_work, NON_CRIB_POS, crib_pos_list, crib_pt_nums)

        c1 = nd <= OBS_NULL_DISTINCT
        c2 = kp >= OBS_KS_PALETTE

        if c1:
            b_hits_c1_only += 1
        if c2:
            b_hits_c2_only += 1
        if c1 and c2:
            b_hits_joint += 1
        if c1 or c2:
            b_hits_either += 1

        if report_interval > 0 and (i + 1) % report_interval == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed
            p_joint = b_hits_joint / (i + 1) if b_hits_joint > 0 else 0
            print(f"  {i+1:>12,} / {n_trials_b:,}  "
                  f"joint={b_hits_joint}  c1={b_hits_c1_only}  c2={b_hits_c2_only}  "
                  f"p_joint={p_joint:.2e}  ({rate:,.0f} trials/s)")

    b_elapsed = time.time() - t0
    b_p_joint = b_hits_joint / n_trials_b if b_hits_joint > 0 else f"<{1/n_trials_b:.2e}"
    b_p_c1 = b_hits_c1_only / n_trials_b
    b_p_c2 = b_hits_c2_only / n_trials_b

    if isinstance(b_p_joint, float):
        b_ci_lo, b_ci_hi = wilson_ci(b_hits_joint, n_trials_b)
    else:
        b_ci_lo, b_ci_hi = 0, 3 / n_trials_b  # Poisson upper bound

    print(f"\n  Model B results:")
    print(f"    Claim 1 alone:  {b_hits_c1_only} / {n_trials_b:,} = p = {b_p_c1:.3e}")
    print(f"    Claim 2 alone:  {b_hits_c2_only} / {n_trials_b:,} = p = {b_p_c2:.3e}")
    print(f"    JOINT (C1 & C2): {b_hits_joint} / {n_trials_b:,} = p = {b_p_joint}")
    if isinstance(b_p_joint, float):
        print(f"    95% CI: [{b_ci_lo:.3e}, {b_ci_hi:.3e}]")
    else:
        print(f"    Upper bound (95%): {b_ci_hi:.3e}")
    print(f"    Fisher naive (if independent): {b_p_c1 * b_p_c2:.3e}")
    print(f"    Time: {b_elapsed:.1f}s\n")

    results["model_b"] = {
        "description": "Letter-shuffle: permute CT letters, fixed PALETTE {B,G,I,K,O,W,Z}, fixed null positions",
        "n_trials": n_trials_b,
        "hits_c1": b_hits_c1_only,
        "hits_c2": b_hits_c2_only,
        "hits_joint": b_hits_joint,
        "p_c1": b_p_c1,
        "p_c2": b_p_c2 if isinstance(b_p_c2, float) else str(b_p_c2),
        "p_joint": b_p_joint if isinstance(b_p_joint, float) else str(b_p_joint),
        "ci_95_lo": b_ci_lo,
        "ci_95_hi": b_ci_hi,
        "fisher_naive": b_p_c1 * b_p_c2,
        "elapsed_s": round(b_elapsed, 1),
        "note": "Tests both claims jointly. Palette fixed as observed. CT letters shuffled.",
    }

    # ── Model C ──
    print(f"=== MODEL C: Letter-Shuffle, Re-Derive Palette ({n_trials_c:,} trials) ===")
    print("  (Tests: P(null_distinct <= 7 AND ks_enrichment >= 13/24 for DERIVED palette))")
    print("  This is the auditor's recommended 'proper joint null'")
    t0 = time.time()
    c_hits_joint = 0
    c_hits_c1_only = 0
    c_hits_c2_given_c1 = 0  # c2 hits AMONG c1 hits
    c_c1_with_c2_counts = []  # track ks_pal for c1 hits
    report_interval = n_trials_c // 10

    for i in range(n_trials_c):
        rng.shuffle(ct_nums_work)
        nd, kp = model_c_trial(ct_nums_work, crib_pos_list, crib_pt_nums)

        c1 = nd <= OBS_NULL_DISTINCT
        if c1:
            c_hits_c1_only += 1
            # Among C1 hits, how often does the derived palette also enrich the keystream?
            if kp >= OBS_KS_PALETTE:
                c_hits_joint += 1
                c_hits_c2_given_c1 += 1
            c_c1_with_c2_counts.append(kp)

        if report_interval > 0 and (i + 1) % report_interval == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed
            p_joint = c_hits_joint / (i + 1) if c_hits_joint > 0 else 0
            print(f"  {i+1:>12,} / {n_trials_c:,}  "
                  f"c1_hits={c_hits_c1_only}  joint={c_hits_joint}  "
                  f"p_joint={p_joint:.2e}  ({rate:,.0f} trials/s)")

    c_elapsed = time.time() - t0
    c_p_c1 = c_hits_c1_only / n_trials_c
    c_p_joint = c_hits_joint / n_trials_c if c_hits_joint > 0 else f"<{1/n_trials_c:.2e}"

    if isinstance(c_p_joint, float) and c_hits_joint > 0:
        c_ci_lo, c_ci_hi = wilson_ci(c_hits_joint, n_trials_c)
    else:
        c_ci_lo, c_ci_hi = 0, 3 / n_trials_c

    # Conditional: P(ks >= 13 | distinct <= 7)
    if c_hits_c1_only > 0:
        c_p_c2_given_c1 = c_hits_c2_given_c1 / c_hits_c1_only
        c_c2_given_c1_ci_lo, c_c2_given_c1_ci_hi = wilson_ci(c_hits_c2_given_c1, c_hits_c1_only)
        # Distribution of ks_palette among C1 hits
        ks_hist = Counter(c_c1_with_c2_counts)
        mean_ks = sum(c_c1_with_c2_counts) / len(c_c1_with_c2_counts)
    else:
        c_p_c2_given_c1 = None
        c_c2_given_c1_ci_lo = c_c2_given_c1_ci_hi = None
        ks_hist = {}
        mean_ks = None

    print(f"\n  Model C results:")
    print(f"    Claim 1 (distinct <= 7): {c_hits_c1_only} / {n_trials_c:,} = p = {c_p_c1:.3e}")
    print(f"    JOINT (C1 & C2 derived): {c_hits_joint} / {n_trials_c:,} = p = {c_p_joint}")
    if isinstance(c_p_joint, float) and c_hits_joint > 0:
        print(f"    95% CI: [{c_ci_lo:.3e}, {c_ci_hi:.3e}]")
    else:
        print(f"    Upper bound (95%): {c_ci_hi:.3e}")
    if c_p_c2_given_c1 is not None:
        print(f"    P(ks >= 13 | distinct <= 7): {c_hits_c2_given_c1} / {c_hits_c1_only} "
              f"= {c_p_c2_given_c1:.4f}")
        print(f"    95% CI: [{c_c2_given_c1_ci_lo:.4f}, {c_c2_given_c1_ci_hi:.4f}]")
        print(f"    Mean ks_palette among C1 hits: {mean_ks:.2f} (observed: 13)")
    print(f"    Time: {c_elapsed:.1f}s\n")

    results["model_c"] = {
        "description": "Letter-shuffle + re-derive palette from nulls. Proper joint null.",
        "n_trials": n_trials_c,
        "hits_c1": c_hits_c1_only,
        "hits_joint": c_hits_joint,
        "p_c1": c_p_c1,
        "p_joint": c_p_joint if isinstance(c_p_joint, (float, int)) else str(c_p_joint),
        "ci_95_lo": c_ci_lo,
        "ci_95_hi": c_ci_hi,
        "p_c2_given_c1": c_p_c2_given_c1,
        "c2_given_c1_ci": [c_c2_given_c1_ci_lo, c_c2_given_c1_ci_hi] if c_p_c2_given_c1 is not None else None,
        "mean_ks_palette_given_c1": mean_ks,
        "ks_histogram_given_c1": {str(k): v for k, v in sorted(ks_hist.items())} if ks_hist else {},
        "elapsed_s": round(c_elapsed, 1),
        "note": "The auditor's recommended test. Palette re-derived per trial.",
    }

    # ── Summary ──
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Observed: null_distinct=7, ks_palette=13/24")
    print(f"  Model A (pos-shuffle, C1 only):     p = {a_pvalue:.3e}  [{a_ci_lo:.3e}, {a_ci_hi:.3e}]")
    print(f"  Model B (letter-shuffle, fixed pal): p_joint = {b_p_joint}")
    if isinstance(b_p_joint, float):
        print(f"    Fisher naive (if indep):           p = {b_p_c1 * b_p_c2:.3e}")
        dep_ratio = b_p_joint / (b_p_c1 * b_p_c2) if b_p_c1 * b_p_c2 > 0 else float('inf')
        print(f"    Dependence ratio (joint/product):  {dep_ratio:.2f}")
    print(f"  Model C (letter-shuffle, re-derive): p_joint = {c_p_joint}")
    if c_p_c2_given_c1 is not None:
        print(f"    Conditional P(ks>=13|distinct<=7):  {c_p_c2_given_c1:.4f}")
    print("=" * 70)

    # Write results
    outpath = os.path.join(_ROOT, "results", "e_joint_null_simulation.json")
    with open(outpath, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults written to {outpath}")

    return results


def wilson_ci(hits, n, z=1.96):
    """Wilson score confidence interval for a proportion."""
    if n == 0:
        return 0.0, 1.0
    p_hat = hits / n
    denom = 1 + z ** 2 / n
    center = (p_hat + z ** 2 / (2 * n)) / denom
    margin = z * math.sqrt(p_hat * (1 - p_hat) / n + z ** 2 / (4 * n ** 2)) / denom
    return max(0, center - margin), min(1, center + margin)


if __name__ == "__main__":
    # Default: 5M each for initial run (takes ~10-20 min on 1 core)
    # For publication: increase to 50M (multiply times by 10)
    N_A = 5_000_000
    N_B = 5_000_000
    N_C = 5_000_000
    SEED = 20260320

    # Allow command-line override
    if len(sys.argv) > 1:
        try:
            scale = int(sys.argv[1])
            N_A = scale
            N_B = scale
            N_C = scale
            print(f"Using {scale:,} trials per model (from command line)")
        except ValueError:
            pass

    print(f"Joint Null Simulation for K4 Claims 1+2")
    print(f"Trials per model: {N_A:,} / {N_B:,} / {N_C:,}")
    print(f"Seed: {SEED}")
    print(f"Observed: null_distinct=7, ks_palette=13/24, palette={sorted(PALETTE)}")
    print()

    run_simulation(N_A, N_B, N_C, SEED)
