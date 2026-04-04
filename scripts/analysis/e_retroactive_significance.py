#!/usr/bin/env python3
"""Retroactive statistical significance audit of all stored results.

Cipher: n/a (meta-analysis)
Family: analysis
Status: active
Keyspace: n/a
Last run: never
Best score: n/a

Applies score_significance() to every result in the exhaustion log
and results database to determine which "interesting" findings actually
survive multiple testing correction.

This is the statistical audit that should have existed from the start.
"""
import sys
import os
import json
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.scoring.stats import (
    null_score_distribution, score_significance, fdr_correct,
)


def main():
    print("=" * 70)
    print("RETROACTIVE STATISTICAL SIGNIFICANCE AUDIT")
    print("=" * 70)

    # Step 1: Build a large null distribution (once)
    print("\nBuilding null distribution (200K trials)...")
    t0 = time.time()
    null = null_score_distribution(n_trials=200_000, seed=42)
    elapsed = time.time() - t0
    print(f"  Done in {elapsed:.1f}s")
    print(f"  Null mean: {null.mean():.3f}")
    print(f"  Null std:  {null.std():.3f}")
    print(f"  Null max:  {null.max()}")
    print(f"  Null P(>=3): {(null >= 3).mean():.4f}")
    print(f"  Null P(>=4): {(null >= 4).mean():.4f}")
    print(f"  Null P(>=5): {(null >= 5).mean():.4f}")
    print(f"  Null P(>=6): {(null >= 6).mean():.4f}")
    print(f"  Null P(>=7): {(null >= 7).mean():.4f}")
    print(f"  Null P(>=8): {(null >= 8).mean():.4f}")

    # Step 2: Analyze exhaustion log for best scores
    print("\nAnalyzing exhaustion log...")
    with open(os.path.join(_ROOT, "exhaustion_log.json")) as f:
        elog = json.load(f)

    entries_with_scores = []
    for script_id, entry in elog.items():
        best = entry.get("best_score")
        if best is None:
            # Try to extract from description or other fields
            continue
        try:
            best = float(best)
        except (ValueError, TypeError):
            continue
        if best > 0:
            keyspace = entry.get("keyspace", "unknown")
            try:
                n_configs = int(str(keyspace).replace(",", "").replace("~", "").split()[0])
            except (ValueError, IndexError):
                n_configs = 10000  # conservative default
            entries_with_scores.append({
                "script_id": script_id,
                "best_score": int(best),
                "n_configs": n_configs,
                "family": entry.get("family", "unknown"),
                "status": entry.get("status", "unknown"),
            })

    print(f"  Found {len(entries_with_scores)} scripts with reported scores")

    # Step 3: Compute significance for each
    print("\nComputing significance...")
    significant_results = []
    marginal_results = []
    noise_results = []

    for entry in entries_with_scores:
        sig = score_significance(
            entry["best_score"],
            entry["n_configs"],
            null_distribution=null,
        )

        entry["raw_pvalue"] = sig["raw_pvalue"]
        entry["bonferroni_pvalue"] = sig["bonferroni_pvalue"]
        entry["expected_max"] = sig["expected_max_score"]
        entry["verdict"] = sig["verdict"]

        if sig["is_significant_bonferroni"]:
            significant_results.append(entry)
        elif sig["bonferroni_pvalue"] < 0.1:
            marginal_results.append(entry)
        else:
            noise_results.append(entry)

    # Step 4: Report
    print(f"\n{'=' * 70}")
    print(f"RESULTS")
    print(f"{'=' * 70}")
    print(f"\n  Significant (Bonferroni p < 0.05): {len(significant_results)}")
    print(f"  Marginal (0.05 <= p < 0.1):        {len(marginal_results)}")
    print(f"  Noise (p >= 0.1):                   {len(noise_results)}")

    if significant_results:
        print(f"\n--- SIGNIFICANT RESULTS ---")
        for r in sorted(significant_results, key=lambda x: x["bonferroni_pvalue"]):
            print(f"  {r['script_id']}: score={r['best_score']}/24, "
                  f"n={r['n_configs']}, p_bonf={r['bonferroni_pvalue']:.2e}, "
                  f"E[max]={r['expected_max']:.1f}")

    if marginal_results:
        print(f"\n--- MARGINAL RESULTS ---")
        for r in sorted(marginal_results, key=lambda x: x["bonferroni_pvalue"]):
            print(f"  {r['script_id']}: score={r['best_score']}/24, "
                  f"n={r['n_configs']}, p_bonf={r['bonferroni_pvalue']:.3f}, "
                  f"E[max]={r['expected_max']:.1f}")

    # Step 5: Score distribution analysis
    print(f"\n--- SCORE DISTRIBUTION ---")
    from collections import Counter
    score_dist = Counter(e["best_score"] for e in entries_with_scores)
    for score in sorted(score_dist.keys()):
        print(f"  Score {score:2d}: {score_dist[score]:3d} scripts")

    # Step 6: Common significance thresholds
    print(f"\n--- SIGNIFICANCE REFERENCE TABLE ---")
    print(f"  (Score needed for significance at various config counts)")
    print(f"  {'N configs':>12s}  {'Score for p<0.05':>16s}  {'E[max]':>8s}")
    for n in [100, 1000, 10000, 100000, 1000000, 10000000]:
        # Find minimum score with p < 0.05 after Bonferroni
        for s in range(24, -1, -1):
            sig = score_significance(s, n, null_distribution=null)
            if not sig["is_significant_bonferroni"]:
                min_sig = s + 1
                break
        else:
            min_sig = 0
        emax = score_significance(0, n, null_distribution=null)["expected_max_score"]
        print(f"  {n:>12,d}  {min_sig:>16d}/24  {emax:>8.1f}")

    # Save
    outpath = os.path.join(_ROOT, "results", "retroactive_significance_audit.json")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "retroactive_significance_audit",
            "null_mean": float(null.mean()),
            "null_std": float(null.std()),
            "null_max": int(null.max()),
            "n_scripts_analyzed": len(entries_with_scores),
            "n_significant": len(significant_results),
            "n_marginal": len(marginal_results),
            "n_noise": len(noise_results),
            "significant": significant_results,
            "marginal": marginal_results,
        }, f, indent=2, default=str)
    print(f"\nResults saved: {outpath}")


if __name__ == "__main__":
    main()
