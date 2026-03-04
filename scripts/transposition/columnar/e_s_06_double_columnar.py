#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-06: Double columnar transposition + periodic Vigenère.

HYPOTHESIS: K4 uses double columnar transposition (a WWII-era cipher)
combined with Vigenère substitution.

Model tested: CT = trans2(trans1(vig(PT, periodic_key)))
- Encrypt: Vigenère first, then two columnar transpositions.
- Key is at original PT positions; test periodicity at periods 3-15.

Width pairs: exhaustive for both widths ≤ 7, then (7,8)/(8,7)/(8,8).
Total configs for (7,7): 5040² = 25.4M.

This is the highest-priority untested hypothesis family (Tier 4, 0% tested).
"""

import json
import math
import os
import sys
import time
from collections import defaultdict
from itertools import permutations as iter_perms

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_ENTRIES, N_CRIBS, MOD,
    NOISE_FLOOR, SIGNAL_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import columnar_perm, invert_perm


# ═══ Constants ═══════════════════════════════════════════════════════════

CT_INT = np.array([ord(c) - 65 for c in CT], dtype=np.int16)

# Sort cribs by position (they already are, but be explicit)
_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = np.array([p for p, _ in _sorted], dtype=np.int32)
PT_CRIB = np.array([ord(c) - 65 for _, c in _sorted], dtype=np.int16)
assert len(CRIB_POS) == N_CRIBS == 24

PERIODS = list(range(3, 16))

# Precompute period groups: crib INDICES grouped by (crib_position mod period)
PERIOD_GROUPS = {}
for per in PERIODS:
    groups = defaultdict(list)
    for idx, pos in enumerate(CRIB_POS):
        groups[int(pos) % per].append(idx)
    PERIOD_GROUPS[per] = groups

# Approximate noise floors (from prior Monte Carlo / theory)
NOISE_FLOORS = {
    3: 5.0, 4: 5.8, 5: 6.5, 6: 7.2, 7: 8.2, 8: 9.2,
    9: 10.0, 10: 11.0, 11: 12.0, 12: 13.0, 13: 13.5, 14: 14.5, 15: 15.5,
}


# ═══ Permutation generation ═════════════════════════════════════════════

def gen_all_inv_perms(width, length=CT_LEN):
    """Generate all inverse columnar permutations for given width.
    Returns array of shape (factorial(width), length), dtype int16.
    """
    n = math.factorial(width)
    arr = np.empty((n, length), dtype=np.int16)
    for idx, order in enumerate(iter_perms(range(width))):
        perm = columnar_perm(width, order, length)
        arr[idx] = invert_perm(perm)
    return arr


# ═══ Scoring ═════════════════════════════════════════════════════════════

def score_period_batch(key_vals, period):
    """Score period consistency via majority voting, vectorized over rows.

    key_vals: shape (N, 24), values in [0, 25]
    Returns: shape (N,) — total matches (majority count per group, summed).
    """
    groups = PERIOD_GROUPS[period]
    N = key_vals.shape[0]
    total = np.zeros(N, dtype=np.int32)

    for indices in groups.values():
        k = len(indices)
        if k == 1:
            total += 1
            continue

        gcols = key_vals[:, indices]  # (N, k)

        # For each element in group, count how many match it. Take max.
        best = np.ones(N, dtype=np.int32)
        for r in range(k):
            ref = gcols[:, r:r + 1]  # (N, 1)
            cnt = np.sum(gcols == ref, axis=1)  # (N,)
            best = np.maximum(best, cnt)

        total += best

    return total


def score_model2_single(key_positions, key_values, period):
    """Score 'sub∘trans' model for a single candidate.

    key_positions: shape (24,) — where the key lives (varies per perm)
    key_values: shape (24,) — key values
    Returns: int — consistency score
    """
    groups = defaultdict(list)
    for idx in range(len(key_positions)):
        groups[int(key_positions[idx]) % period].append(idx)

    total = 0
    for indices in groups.values():
        k = len(indices)
        if k == 1:
            total += 1
            continue
        vals = [int(key_values[idx]) for idx in indices]
        # Majority count
        from collections import Counter
        best_count = Counter(vals).most_common(1)[0][1]
        total += best_count
    return total


# ═══ Main search ═════════════════════════════════════════════════════════

def search_double_columnar(w1, w2, threshold=12):
    """Exhaustive double columnar search for width pair (w1, w2).

    Model: CT = trans2(trans1(vig(PT, periodic_key)))
    Key at original PT positions. Check periodicity at periods 3-15.
    """
    n1 = math.factorial(w1)
    n2 = math.factorial(w2)
    total = n1 * n2

    print(f"\n{'=' * 60}")
    print(f"  Double Columnar ({w1},{w2}): {n1:,} x {n2:,} = {total:,}")
    print(f"{'=' * 60}")
    sys.stdout.flush()

    inv1 = gen_all_inv_perms(w1)  # (n1, 97)
    inv2 = gen_all_inv_perms(w2)  # (n2, 97)

    best_per_period = {p: {"score": 0, "s1": -1, "s2": -1} for p in PERIODS}
    best_overall = {"score": 0, "period": 0, "s1": -1, "s2": -1}
    top_results = []  # (score, period, s1, s2)

    t0 = time.time()
    report_interval = max(1, n1 // 20)

    for s1 in range(n1):
        # Where do crib positions land after undoing first transposition?
        inter = inv1[s1][CRIB_POS]  # shape (24,) int16

        # For all s2: where do they land after undoing both?
        final = inv2[:, inter]  # shape (n2, 24)

        # CT values at those positions
        ct_at = CT_INT[final]  # shape (n2, 24)

        # Derive key values: key[p] = (CT[combined_inv[p]] - PT[p]) mod 26
        kv = (ct_at - PT_CRIB[np.newaxis, :]) % MOD  # shape (n2, 24)

        # Score each period
        for p in PERIODS:
            scores = score_period_batch(kv, p)

            mx_idx = int(np.argmax(scores))
            mx_val = int(scores[mx_idx])

            if mx_val > best_per_period[p]["score"]:
                best_per_period[p] = {"score": mx_val, "s1": s1, "s2": mx_idx}

            if mx_val > best_overall["score"] or \
               (mx_val == best_overall["score"] and p < best_overall["period"]):
                best_overall = {
                    "score": mx_val, "period": p,
                    "s1": s1, "s2": mx_idx,
                }

            # Collect anything above threshold
            if mx_val >= threshold:
                hits = np.where(scores >= threshold)[0]
                for h in hits[:10]:  # cap per-batch to avoid memory explosion
                    top_results.append((int(scores[h]), p, s1, int(h)))

        # Progress report
        if s1 == 0 or (s1 + 1) % report_interval == 0 or s1 == n1 - 1:
            elapsed = time.time() - t0
            checked = (s1 + 1) * n2
            rate = checked / elapsed if elapsed > 0 else 0
            pct = 100.0 * (s1 + 1) / n1
            eta = (n1 - s1 - 1) * (elapsed / (s1 + 1)) if s1 > 0 else 0
            print(f"  [{s1+1:>5}/{n1}] {pct:5.1f}%  {rate:>10,.0f}/s  "
                  f"ETA {eta:>6.0f}s  best={best_overall['score']}/24 @p={best_overall['period']}")
            sys.stdout.flush()

    elapsed = time.time() - t0

    # ── Model 2 post-check on top candidates ──
    # For top results, also check "sub∘trans" model: key at positions final[p]
    model2_best = {"score": 0, "period": 0, "s1": -1, "s2": -1}
    top_sorted = sorted(top_results, key=lambda x: -x[0])[:200]
    for score, per, s1, s2 in top_sorted:
        inter = inv1[s1][CRIB_POS]
        final_single = inv2[s2][inter]  # shape (24,)
        kv_single = (CT_INT[final_single] - PT_CRIB) % MOD

        for p in PERIODS:
            m2_score = score_model2_single(final_single, kv_single, p)
            if m2_score > model2_best["score"] or \
               (m2_score == model2_best["score"] and p < model2_best["period"]):
                model2_best = {"score": m2_score, "period": p, "s1": s1, "s2": s2}

    # ── Period breakdown ──
    period_summary = {}
    for p in PERIODS:
        b = best_per_period[p]
        noise = NOISE_FLOORS.get(p, p)
        period_summary[p] = {
            "best_score": b["score"],
            "noise_floor": noise,
            "excess": round(b["score"] - noise, 1),
            "s1": b["s1"], "s2": b["s2"],
        }

    print(f"\n  Period breakdown (model 1 = trans∘sub):")
    for p in [3, 5, 7, 10, 13]:
        if p in period_summary:
            ps = period_summary[p]
            flag = " ***" if ps["excess"] > 4 else ""
            print(f"    p={p:>2}: best {ps['best_score']:>2}/24  "
                  f"noise~{ps['noise_floor']:.0f}  excess={ps['excess']:+.1f}{flag}")

    if model2_best["score"] > 0:
        print(f"  Model 2 (sub∘trans) best: {model2_best['score']}/24 @p={model2_best['period']}")

    n_signals = sum(1 for s, p, _, _ in top_results if s >= SIGNAL_THRESHOLD)
    print(f"\n  RESULT ({w1},{w2}): best={best_overall['score']}/24 @p={best_overall['period']} "
          f"| {total:,} configs | {elapsed:.1f}s | signals(>=18): {n_signals}")
    sys.stdout.flush()

    return {
        "w1": w1, "w2": w2,
        "total_configs": total,
        "elapsed_s": round(elapsed, 1),
        "rate_per_s": round(total / elapsed) if elapsed > 0 else 0,
        "best_model1": best_overall,
        "best_model2": model2_best,
        "per_period": period_summary,
        "n_signals": n_signals,
        "n_above_threshold": len(top_results),
    }


def main():
    t_start = time.time()

    print("=" * 60)
    print("E-S-06: Double Columnar Transposition + Periodic Vigenere")
    print("=" * 60)
    print(f"Model: CT = trans2(trans1(vig(PT, periodic_key)))")
    print(f"CT: {CT[:20]}...{CT[-10:]} ({CT_LEN} chars)")
    print(f"Cribs: {N_CRIBS} positions (ENE 21-33, BC 63-73)")
    print(f"Periods: {PERIODS[0]}-{PERIODS[-1]}")
    print()

    # Noise floor reference
    print("Noise floors (approximate expected random scores):")
    for p in [3, 5, 7, 10, 13]:
        print(f"  Period {p:>2}: ~{NOISE_FLOORS[p]:.1f}/24")
    print()

    # Width pairs, ordered by search space size
    pairs = [
        (5, 5),   # 120^2 = 14.4K
        (5, 6),   # 120 × 720 = 86.4K
        (6, 5),   # 720 × 120 = 86.4K
        (5, 7),   # 120 × 5040 = 604.8K
        (7, 5),   # 5040 × 120 = 604.8K
        (6, 6),   # 720^2 = 518.4K
        (6, 7),   # 720 × 5040 = 3.6M
        (7, 6),   # 5040 × 720 = 3.6M
        (7, 7),   # 5040^2 = 25.4M
        (7, 8),   # 5040 × 40320 = 203M
        (8, 7),   # 40320 × 5040 = 203M
    ]

    all_results = {}

    for w1, w2 in pairs:
        result = search_double_columnar(w1, w2)
        all_results[f"{w1}x{w2}"] = result

        # Alert check
        if result["n_signals"] > 0:
            print(f"\n{'!' * 60}")
            print(f"  SIGNAL DETECTED at ({w1},{w2})!")
            print(f"{'!' * 60}")
            sys.stdout.flush()

    # ═══ Final summary ═══════════════════════════════════════════════════
    t_total = time.time() - t_start
    total_configs = sum(r["total_configs"] for r in all_results.values())

    print(f"\n{'=' * 60}")
    print(f"  FINAL SUMMARY — Double Columnar + Periodic Vigenere")
    print(f"{'=' * 60}")
    print(f"  Total configs: {total_configs:,}")
    print(f"  Total time: {t_total:.0f}s ({t_total / 60:.1f} min)")
    print()

    # Best at meaningful periods across all pairs
    print(f"  Best scores at meaningful periods (<=7):")
    max_meaningful = 0
    for p in [3, 4, 5, 6, 7]:
        best = 0
        best_pair = ""
        for key, result in all_results.items():
            ps = result["per_period"].get(p, {})
            if ps.get("best_score", 0) > best:
                best = ps["best_score"]
                best_pair = key
        noise = NOISE_FLOORS.get(p, p)
        excess = best - noise
        print(f"    p={p}: best={best}/24 ({best_pair}) noise~{noise:.0f} excess={excess:+.1f}")
        max_meaningful = max(max_meaningful, best)

    # Verdict
    if max_meaningful >= SIGNAL_THRESHOLD:
        verdict = "SIGNAL"
    elif max_meaningful <= NOISE_FLOORS[7] + 3:
        verdict = "ELIMINATED"
    else:
        verdict = "INCONCLUSIVE"

    print(f"\n  Best meaningful score (p<=7): {max_meaningful}/24")
    print(f"  Noise floor at p=7: ~{NOISE_FLOORS[7]:.1f}/24")
    print(f"  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_06_double_columnar.json"
    output = {
        "experiment": "E-S-06",
        "hypothesis": "Double columnar transposition + periodic Vigenere",
        "model": "CT = trans2(trans1(vig(PT, periodic_key)))",
        "total_configs": total_configs,
        "total_time_s": round(t_total, 1),
        "verdict": verdict,
        "best_meaningful_score": max_meaningful,
        "pairs_tested": list(all_results.keys()),
        "results_by_pair": all_results,
    }
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_06_double_columnar.py")
    print(f"\nRESULT: best={max_meaningful}/24 configs={total_configs} verdict={verdict}")

    return verdict


if __name__ == "__main__":
    main()
