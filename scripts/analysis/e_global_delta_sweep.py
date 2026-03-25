#!/usr/bin/env python3
"""
Cipher: stego_analysis
Family: analysis
Status: active
Keyspace: analytical (48 lags x 26 deltas = 1,248 tests)
Last run:
Best score:
"""
"""
E-GLOBAL-DELTA-SWEEP: Phase 2 of Stego Layer Solve Plan

Test whether there is a GLOBAL constant-difference rule that null values
were chosen to satisfy. For each lag d in {1,...,48} and delta v in {0,...,25},
count pairs (i, i+d) where CT[i+d] - CT[i] ≡ v (mod 26).

Pairs are categorized into three classes:
  (a) both positions non-null ("NN")
  (b) exactly one position is null ("mixed")
  (c) both positions are null ("null-null")

For each (lag, delta), we compute a z-score for enrichment of that delta
among null-involved pairs vs non-null pairs. Bonferroni correction is applied
(k = 48 × 26 = 1,248 tests). A Monte Carlo baseline (100K shuffles) gives
the empirical distribution of max z-scores under random null placement.

Output: results/global_delta_rule_sweep.json
Repro: PYTHONPATH=src python3 -u scripts/analysis/e_global_delta_sweep.py
"""

import json
import sys
import os
import time
import random
from collections import defaultdict
from math import sqrt

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CONSENSUS_NULL_POSITIONS, NULL_PALETTE
)

# ── Helpers ──────────────────────────────────────────────────────────────

CT_NUMS = [ALPH_IDX[c] for c in CT]
NULL_SET = set(CONSENSUS_NULL_POSITIONS)
N_TESTS = 48 * 26  # Bonferroni correction factor

def classify_pairs(null_set, max_lag=48):
    """
    For each lag d in [1, max_lag], classify all pairs (i, i+d) and
    compute delta distribution per category.

    Returns dict: lag -> { 'nn': Counter[delta], 'mixed': Counter[delta], 'nullnull': Counter[delta] }
    """
    result = {}
    for d in range(1, max_lag + 1):
        nn = defaultdict(int)
        mixed = defaultdict(int)
        nullnull = defaultdict(int)
        for i in range(CT_LEN - d):
            j = i + d
            delta = (CT_NUMS[j] - CT_NUMS[i]) % MOD
            i_null = i in null_set
            j_null = j in null_set
            if not i_null and not j_null:
                nn[delta] += 1
            elif i_null and j_null:
                nullnull[delta] += 1
            else:
                mixed[delta] += 1
        result[d] = {'nn': dict(nn), 'mixed': dict(mixed), 'nullnull': dict(nullnull)}
    return result


def compute_enrichment(pair_data, max_lag=48):
    """
    For each (lag, delta), test whether delta v is enriched among
    null-involved pairs (mixed + nullnull) compared to non-null pairs.

    Uses a two-proportion z-test:
      p_null = count_null_v / total_null
      p_nn   = count_nn_v / total_nn
      z = (p_null - p_nn) / sqrt(p_hat * (1-p_hat) * (1/total_null + 1/total_nn))

    Returns list of (lag, delta, z_score, p_value_bonferroni, counts_dict)
    sorted by |z| descending.
    """
    from scipy.stats import norm  # deferred import; fallback below
    results = []

    for d in range(1, max_lag + 1):
        nn = pair_data[d]['nn']
        mixed = pair_data[d]['mixed']
        nullnull = pair_data[d]['nullnull']

        total_nn = sum(nn.values())
        total_mixed = sum(mixed.values())
        total_nullnull = sum(nullnull.values())
        total_null_involved = total_mixed + total_nullnull

        if total_nn == 0 or total_null_involved == 0:
            continue

        for v in range(MOD):
            c_nn = nn.get(v, 0)
            c_null = mixed.get(v, 0) + nullnull.get(v, 0)

            p_nn = c_nn / total_nn
            p_null = c_null / total_null_involved

            # Pooled proportion
            p_hat = (c_nn + c_null) / (total_nn + total_null_involved)
            if p_hat == 0 or p_hat == 1:
                continue

            se = sqrt(p_hat * (1 - p_hat) * (1/total_nn + 1/total_null_involved))
            if se == 0:
                continue

            z = (p_null - p_nn) / se
            # Two-sided p-value
            p_raw = 2 * norm.sf(abs(z))
            p_bonf = min(p_raw * N_TESTS, 1.0)

            results.append({
                'lag': d,
                'delta': v,
                'z_score': round(z, 4),
                'p_raw': p_raw,
                'p_bonferroni': round(p_bonf, 6),
                'count_nn': c_nn,
                'count_null_involved': c_null,
                'total_nn': total_nn,
                'total_null_involved': total_null_involved,
                'prop_nn': round(p_nn, 4),
                'prop_null': round(p_null, 4),
            })

    results.sort(key=lambda x: abs(x['z_score']), reverse=True)
    return results


def mc_max_z(n_trials=100000, max_lag=48, seed=42):
    """
    Monte Carlo baseline: shuffle null positions among all 97 positions
    (keeping 17 nulls), recompute max |z| across all (lag, delta) pairs.
    Returns list of max |z| values.
    """
    from scipy.stats import norm
    rng = random.Random(seed)
    all_positions = list(range(CT_LEN))
    max_zs = []

    for trial in range(n_trials):
        shuffled_nulls = set(rng.sample(all_positions, len(NULL_SET)))
        # Quick computation: for each lag, count deltas by category
        best_z = 0.0
        for d in range(1, max_lag + 1):
            nn = defaultdict(int)
            null_inv = defaultdict(int)
            for i in range(CT_LEN - d):
                j = i + d
                delta = (CT_NUMS[j] - CT_NUMS[i]) % MOD
                i_n = i in shuffled_nulls
                j_n = j in shuffled_nulls
                if not i_n and not j_n:
                    nn[delta] += 1
                else:
                    null_inv[delta] += 1

            total_nn = sum(nn.values())
            total_ni = sum(null_inv.values())
            if total_nn == 0 or total_ni == 0:
                continue

            for v in range(MOD):
                c_nn = nn.get(v, 0)
                c_ni = null_inv.get(v, 0)
                p_hat = (c_nn + c_ni) / (total_nn + total_ni)
                if p_hat == 0 or p_hat == 1:
                    continue
                se = sqrt(p_hat * (1 - p_hat) * (1/total_nn + 1/total_ni))
                if se == 0:
                    continue
                z = abs((c_ni / total_ni - c_nn / total_nn) / se)
                if z > best_z:
                    best_z = z
        max_zs.append(best_z)

        if (trial + 1) % 10000 == 0:
            print(f"  MC trial {trial+1}/{n_trials}, running max-z median: {sorted(max_zs)[len(max_zs)//2]:.3f}", flush=True)

    return max_zs


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-GLOBAL-DELTA-SWEEP: Phase 2 — Global constant-difference rule test")
    print("=" * 70)
    print(f"CT length: {CT_LEN}")
    print(f"Null positions ({len(NULL_SET)}): {sorted(NULL_SET)}")
    print(f"Palette: {sorted(NULL_PALETTE)}")
    print(f"Max lag: 48, Deltas: 0-25, Tests: {N_TESTS}")
    print()

    # Try scipy; if unavailable, use a crude normal approximation
    try:
        from scipy.stats import norm as _norm
        HAVE_SCIPY = True
        print("[OK] scipy available for exact p-values")
    except ImportError:
        HAVE_SCIPY = False
        print("[WARN] scipy not available; using math.erfc approximation")
        # Monkey-patch a minimal norm.sf
        import math
        class _NormFallback:
            @staticmethod
            def sf(x):
                return 0.5 * math.erfc(x / math.sqrt(2))
        import scipy
        scipy.stats = type('', (), {'norm': _NormFallback})()

    # ── Step 1: Classify all pairs ──────────────────────────────────────
    print("\n--- Step 1: Pair classification ---")
    pair_data = classify_pairs(NULL_SET)

    # Summary stats
    for d in [1, 2, 4, 7, 8, 13]:
        nn_total = sum(pair_data[d]['nn'].values())
        mixed_total = sum(pair_data[d]['mixed'].values())
        nullnull_total = sum(pair_data[d]['nullnull'].values())
        print(f"  Lag {d:2d}: NN={nn_total}, mixed={mixed_total}, null-null={nullnull_total}")

    # ── Step 2: Enrichment z-scores ─────────────────────────────────────
    print("\n--- Step 2: Enrichment analysis (two-proportion z-test) ---")
    enrichment = compute_enrichment(pair_data)

    # Report top 20
    print(f"\nTop 20 (lag, delta) pairs by |z|:")
    print(f"{'Lag':>4} {'Delta':>5} {'z':>8} {'p_raw':>12} {'p_bonf':>10} {'NN':>4}/{' tot':>4} {'NI':>4}/{' tot':>4}")
    sig_after_bonf = []
    for r in enrichment[:20]:
        flag = " ***" if r['p_bonferroni'] < 0.05 else ""
        print(f"  {r['lag']:3d}   {r['delta']:3d}  {r['z_score']:+7.3f}  {r['p_raw']:12.2e}  {r['p_bonferroni']:9.6f}"
              f"  {r['count_nn']:3d}/{r['total_nn']:4d}  {r['count_null_involved']:3d}/{r['total_null_involved']:4d}{flag}")
        if r['p_bonferroni'] < 0.05:
            sig_after_bonf.append(r)

    n_sig = len(sig_after_bonf)
    print(f"\nSignificant after Bonferroni (p < 0.05): {n_sig}")
    if sig_after_bonf:
        for r in sig_after_bonf:
            print(f"  lag={r['lag']}, delta={r['delta']}, z={r['z_score']:+.3f}, p_bonf={r['p_bonferroni']:.6f}")

    # ── Step 3: Monte Carlo baseline ────────────────────────────────────
    print("\n--- Step 3: Monte Carlo baseline (100K shuffles) ---")
    print("  Shuffling null positions, computing max |z| per trial...")
    mc_zs = mc_max_z(n_trials=100000)

    mc_zs_sorted = sorted(mc_zs)
    mc_median = mc_zs_sorted[len(mc_zs_sorted) // 2]
    mc_95 = mc_zs_sorted[int(0.95 * len(mc_zs_sorted))]
    mc_99 = mc_zs_sorted[int(0.99 * len(mc_zs_sorted))]
    mc_999 = mc_zs_sorted[int(0.999 * len(mc_zs_sorted))]

    observed_max_z = abs(enrichment[0]['z_score']) if enrichment else 0
    mc_rank = sum(1 for z in mc_zs if z >= observed_max_z)
    mc_p = mc_rank / len(mc_zs)

    print(f"\n  MC distribution of max |z| (100K trials):")
    print(f"    Median: {mc_median:.3f}")
    print(f"    95th:   {mc_95:.3f}")
    print(f"    99th:   {mc_99:.3f}")
    print(f"    99.9th: {mc_999:.3f}")
    print(f"  Observed max |z|: {observed_max_z:.3f}")
    print(f"  MC p-value (rank): {mc_p:.5f} ({mc_rank}/{len(mc_zs)} trials >= observed)")

    elapsed = time.time() - t0

    # ── Verdict ─────────────────────────────────────────────────────────
    if mc_p < 0.01:
        verdict = "SIGNIFICANT"
        verdict_detail = f"Observed max |z| = {observed_max_z:.3f} exceeds 99% of random shuffles (MC p = {mc_p:.5f})"
    elif mc_p < 0.05:
        verdict = "MARGINAL"
        verdict_detail = f"Observed max |z| = {observed_max_z:.3f} exceeds 95% of random shuffles (MC p = {mc_p:.5f})"
    else:
        verdict = "NOT SIGNIFICANT"
        verdict_detail = f"Observed max |z| = {observed_max_z:.3f} is within normal range (MC p = {mc_p:.5f})"

    print(f"\n{'=' * 70}")
    print(f"VERDICT: {verdict}")
    print(f"  {verdict_detail}")
    print(f"  Elapsed: {elapsed:.1f}s")
    print(f"{'=' * 70}")

    # ── Save artifact ───────────────────────────────────────────────────
    artifact = {
        'experiment': 'E-GLOBAL-DELTA-SWEEP',
        'description': 'Phase 2: Global constant-difference rule sweep across all lags and deltas',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'parameters': {
            'max_lag': 48,
            'deltas': 26,
            'n_tests_bonferroni': N_TESTS,
            'mc_trials': 100000,
        },
        'null_positions': sorted(NULL_SET),
        'palette': sorted(NULL_PALETTE),
        'verdict': verdict,
        'verdict_detail': verdict_detail,
        'observed_max_z': observed_max_z,
        'mc_distribution': {
            'median': round(mc_median, 4),
            'p95': round(mc_95, 4),
            'p99': round(mc_99, 4),
            'p999': round(mc_999, 4),
        },
        'mc_p_value': round(mc_p, 6),
        'n_significant_bonferroni': n_sig,
        'significant_pairs': sig_after_bonf,
        'top_20_pairs': enrichment[:20],
        'elapsed_seconds': round(elapsed, 1),
    }

    out_path = os.path.join(_ROOT, 'results', 'global_delta_rule_sweep.json')
    with open(out_path, 'w') as f:
        json.dump(artifact, f, indent=2)
    print(f"\nArtifact saved: {out_path}")


if __name__ == '__main__':
    main()
