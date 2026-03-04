#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-07: Simulated annealing over arbitrary permutations.

HYPOTHESIS: K4 uses SOME transposition (not necessarily columnar)
combined with periodic Vigenère substitution.

Model: CT = sigma(vig(PT, periodic_key)) for general sigma in S_97.
Fitness: period consistency at best period (3-15) on crib-derived key values.

This is structure-agnostic: can find columnar, double columnar, route,
strip, spiral, or any other transposition family.

SA with incremental fitness: swapping two positions in sigma only changes
key values at crib positions mapped through those positions. Most swaps
don't touch any crib position (~50% are no-ops), making this very fast.
"""

import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_ENTRIES, N_CRIBS, MOD,
    NOISE_FLOOR, SIGNAL_THRESHOLD,
)

# ═══ Constants ═══════════════════════════════════════════════════════════

CT_INT = [ord(c) - 65 for c in CT]

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = [p for p, _ in _sorted]
PT_CRIB_VAL = {p: ord(c) - 65 for p, c in _sorted}
CRIB_SET = set(CRIB_POS)

PERIODS = list(range(3, 16))

# Precompute period groups for model 1 (key at fixed crib positions)
PERIOD_GROUPS = {}
for per in PERIODS:
    groups = defaultdict(list)
    for p in CRIB_POS:
        groups[p % per].append(p)
    PERIOD_GROUPS[per] = groups


# ═══ Scoring ═════════════════════════════════════════════════════════════

def compute_key_values(sigma_inv, crib_pos, pt_vals, ct_int):
    """Compute key[p] = (CT[sigma_inv[p]] - PT[p]) mod 26 for all cribs."""
    return {p: (ct_int[sigma_inv[p]] - pt_vals[p]) % 26 for p in crib_pos}


def score_all_periods(key_dict, period_groups, periods):
    """Score period consistency for all periods. Returns (best_score, best_period)."""
    best_score = 0
    best_period = 0

    for per in periods:
        groups = period_groups[per]
        total = 0
        for indices in groups.values():
            k = len(indices)
            if k == 1:
                total += 1
                continue
            vals = [key_dict[p] for p in indices]
            best_count = Counter(vals).most_common(1)[0][1]
            total += best_count
        if total > best_score or (total == best_score and per < best_period):
            best_score = total
            best_period = per

    return best_score, best_period


def score_single_period(key_dict, period, groups):
    """Score period consistency for a single period."""
    total = 0
    for indices in groups.values():
        k = len(indices)
        if k == 1:
            total += 1
            continue
        vals = [key_dict[p] for p in indices]
        best_count = Counter(vals).most_common(1)[0][1]
        total += best_count
    return total


# ═══ SA Engine ═══════════════════════════════════════════════════════════

def sa_search(
    n_restarts=200,
    steps_per_restart=500_000,
    t_start_temp=5.0,
    t_end_temp=0.01,
    target_period=7,
    seed=42,
):
    """Simulated annealing over S_97 permutations.

    For each restart:
    1. Random initial permutation
    2. SA with exponential cooling
    3. Track best across all restarts
    """
    rng = random.Random(seed)
    n = CT_LEN

    groups = PERIOD_GROUPS[target_period]

    # Precompute: which sigma positions are "interesting"?
    # sigma_inv[p] for p in CRIB_POS gives the CT positions.
    # When we swap sigma[i] and sigma[j], sigma_inv changes at
    # positions old_sigma[i] and old_sigma[j].
    # If either of those is a crib position, key values change.

    global_best = {"score": 0, "period": 0, "sigma_inv": None, "key_dict": None}
    all_bests = []

    # Also track best across ALL periods (not just target)
    global_best_any = {"score": 0, "period": 0}

    t0 = time.time()

    for restart in range(n_restarts):
        # Random permutation (this is sigma, the gather permutation)
        sigma = list(range(n))
        rng.shuffle(sigma)

        # Compute inverse
        sigma_inv = [0] * n
        for i, s in enumerate(sigma):
            sigma_inv[s] = i

        # Compute initial key values and fitness
        key_dict = compute_key_values(sigma_inv, CRIB_POS, PT_CRIB_VAL, CT_INT)
        current_score = score_single_period(key_dict, target_period, groups)

        best_this_restart = current_score
        best_sigma_inv = list(sigma_inv)
        best_key = dict(key_dict)

        # Cooling schedule
        cooling_rate = (t_end_temp / t_start_temp) ** (1.0 / steps_per_restart)
        temp = t_start_temp

        for step in range(steps_per_restart):
            # Pick two random positions to swap in sigma
            i = rng.randrange(n)
            j = rng.randrange(n - 1)
            if j >= i:
                j += 1

            # What values are at these positions?
            a = sigma[i]  # sigma[i] = a, so sigma_inv[a] = i
            b = sigma[j]  # sigma[j] = b, so sigma_inv[b] = j

            # After swap: sigma[i] = b, sigma[j] = a
            # sigma_inv[b] = i, sigma_inv[a] = j

            # Check if a or b is a crib position
            a_is_crib = a in CRIB_SET
            b_is_crib = b in CRIB_SET

            if not a_is_crib and not b_is_crib:
                # No crib positions affected → fitness unchanged
                # Still do the swap to explore the space
                sigma[i], sigma[j] = sigma[j], sigma[i]
                sigma_inv[a], sigma_inv[b] = sigma_inv[b], sigma_inv[a]
                temp *= cooling_rate
                continue

            # Compute new key values at affected positions
            new_key = dict(key_dict)
            if a_is_crib:
                # sigma_inv[a] changes from i to j
                new_key[a] = (CT_INT[j] - PT_CRIB_VAL[a]) % 26
            if b_is_crib:
                # sigma_inv[b] changes from j to i
                new_key[b] = (CT_INT[i] - PT_CRIB_VAL[b]) % 26

            new_score = score_single_period(new_key, target_period, groups)

            # Accept/reject
            delta = new_score - current_score
            if delta > 0 or (temp > 0 and rng.random() < math.exp(delta / temp)):
                # Accept
                sigma[i], sigma[j] = sigma[j], sigma[i]
                sigma_inv[a], sigma_inv[b] = sigma_inv[b], sigma_inv[a]
                key_dict = new_key
                current_score = new_score

                if current_score > best_this_restart:
                    best_this_restart = current_score
                    best_sigma_inv = list(sigma_inv)
                    best_key = dict(key_dict)
            # else: reject (don't apply swap)

            temp *= cooling_rate

        # End of restart — score best across all periods
        best_key_final = compute_key_values(best_sigma_inv, CRIB_POS, PT_CRIB_VAL, CT_INT)
        any_score, any_period = score_all_periods(best_key_final, PERIOD_GROUPS, PERIODS)

        all_bests.append({
            "restart": restart,
            "target_score": best_this_restart,
            "target_period": target_period,
            "best_any_score": any_score,
            "best_any_period": any_period,
        })

        if best_this_restart > global_best["score"] or \
           (best_this_restart == global_best["score"] and target_period < global_best["period"]):
            global_best = {
                "score": best_this_restart,
                "period": target_period,
                "sigma_inv": best_sigma_inv,
                "key_dict": best_key,
            }

        if any_score > global_best_any["score"]:
            global_best_any = {"score": any_score, "period": any_period}

        # Progress
        if (restart + 1) % max(1, n_restarts // 20) == 0 or restart == 0:
            elapsed = time.time() - t0
            print(f"  [{restart+1:>4}/{n_restarts}] "
                  f"this={best_this_restart}/24 @p={target_period}  "
                  f"global={global_best['score']}/24  "
                  f"any_period={global_best_any['score']}/24 @p={global_best_any['period']}  "
                  f"({elapsed:.0f}s)")
            sys.stdout.flush()

    elapsed = time.time() - t0
    return global_best, global_best_any, all_bests, elapsed


def main():
    t_start = time.time()

    print("=" * 60)
    print("E-S-07: SA over Arbitrary Permutations")
    print("=" * 60)
    print(f"Model: CT = sigma(vig(PT, periodic_key))")
    print(f"CT: {CT[:20]}...{CT[-10:]} ({CT_LEN} chars)")
    print(f"Fitness: period consistency at target period")
    print()

    all_results = {}

    # Run SA targeting different periods
    for target_p in [7, 5, 3, 6, 4]:
        print(f"\n{'='*60}")
        print(f"  SA targeting period {target_p}")
        print(f"  Noise floor: ~{NOISE_FLOORS.get(target_p, '?')}/24")
        print(f"{'='*60}")
        sys.stdout.flush()

        best, best_any, bests, elapsed = sa_search(
            n_restarts=200,
            steps_per_restart=500_000,
            target_period=target_p,
            seed=42 + target_p,
        )

        noise = NOISE_FLOORS.get(target_p, 8)
        excess = best["score"] - noise

        print(f"\n  Target p={target_p}: best={best['score']}/24 "
              f"noise~{noise:.0f} excess={excess:+.1f}")
        print(f"  Best across all periods: {best_any['score']}/24 @p={best_any['period']}")

        if best["score"] >= SIGNAL_THRESHOLD:
            print(f"  *** SIGNAL DETECTED ***")
            # Reconstruct the permutation and decrypt
            sigma_inv = best["sigma_inv"]
            key = best["key_dict"]
            # Show key values at crib positions
            key_str = "".join(chr(key.get(p, 0) + 65) for p in CRIB_POS)
            print(f"  Key at cribs: {key_str}")

        # Score distribution
        target_scores = [b["target_score"] for b in bests]
        any_scores = [b["best_any_score"] for b in bests]
        print(f"  Score distribution (target): "
              f"min={min(target_scores)} mean={sum(target_scores)/len(target_scores):.1f} "
              f"max={max(target_scores)}")
        print(f"  Score distribution (any period): "
              f"min={min(any_scores)} mean={sum(any_scores)/len(any_scores):.1f} "
              f"max={max(any_scores)}")

        all_results[f"period_{target_p}"] = {
            "target_period": target_p,
            "best_score": best["score"],
            "best_any_score": best_any["score"],
            "best_any_period": best_any["period"],
            "noise_floor": noise,
            "excess": round(excess, 1),
            "n_restarts": 200,
            "steps_per_restart": 500_000,
            "elapsed_s": round(elapsed, 1),
            "score_distribution": {
                "target_min": min(target_scores),
                "target_mean": round(sum(target_scores) / len(target_scores), 2),
                "target_max": max(target_scores),
                "any_min": min(any_scores),
                "any_mean": round(sum(any_scores) / len(any_scores), 2),
                "any_max": max(any_scores),
            },
        }

    # ═══ Final summary ═══════════════════════════════════════════════════
    t_total = time.time() - t_start

    print(f"\n{'='*60}")
    print(f"  FINAL SUMMARY — SA Permutation Search")
    print(f"{'='*60}")
    print(f"  Total time: {t_total:.0f}s ({t_total/60:.1f} min)")
    print()

    max_meaningful = 0
    for key, result in all_results.items():
        if result["target_period"] <= 7:
            max_meaningful = max(max_meaningful, result["best_score"])
        print(f"  {key}: best={result['best_score']}/24 @p={result['target_period']}  "
              f"noise~{result['noise_floor']:.0f}  excess={result['excess']:+.1f}")

    if max_meaningful >= SIGNAL_THRESHOLD:
        verdict = "SIGNAL"
    elif max_meaningful <= NOISE_FLOORS[7] + 3:
        verdict = "NOISE"
    else:
        verdict = "INCONCLUSIVE"

    print(f"\n  Best meaningful (p<=7): {max_meaningful}/24")
    print(f"  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_07_sa_permutation.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-07",
            "hypothesis": "Arbitrary transposition + periodic Vigenere (SA search)",
            "model": "CT = sigma(vig(PT, periodic_key))",
            "total_time_s": round(t_total, 1),
            "verdict": verdict,
            "best_meaningful_score": max_meaningful,
            "results_by_period": all_results,
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_07_sa_permutation.py")
    print(f"\nRESULT: best={max_meaningful}/24 verdict={verdict}")

    return verdict


# Approximate noise floors
NOISE_FLOORS = {
    3: 5.0, 4: 5.8, 5: 6.5, 6: 7.2, 7: 8.2, 8: 9.2,
    9: 10.0, 10: 11.0, 11: 12.0, 12: 13.0, 13: 13.5, 14: 14.5, 15: 15.5,
}


if __name__ == "__main__":
    main()
