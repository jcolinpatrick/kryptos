#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-33: Fitness Landscape Analysis of the Permutation Space.

Meta-question: Is the crib-scoring fitness landscape over 97-element permutations
smooth enough for stochastic search (SA/hill-climbing) to navigate effectively?
If the landscape is rugged (parent-child scores uncorrelated), SA is no better
than random search. If it's smooth, SA can exploit local gradients.

This experiment directly informs the JTS agent's strategy.

Method:
1. Generate N random permutations
2. For each, score at all discriminating periods (2-7) × 3 variants × 2 models
3. Apply M random single-swap mutations to each parent
4. Score each child
5. Analyze parent-child score correlation, score gradient, landscape ruggedness

Additional analyses:
- Per-period landscape smoothness (is period 5 smoother than period 7?)
- Score autocorrelation over mutation chains (start random, apply K swaps)
- Hamming distance from identity vs score (do near-identity perms score higher?)
- How many swaps needed to get from score 8 to score 12? 15? 18?
"""
import json
import math
import os
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN  # 97


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def strict_periodic_score(inv_perm, period, variant, model):
    """Majority-vote crib scoring."""
    residue_keys = defaultdict(list)
    for pt_pos in sorted(CRIB_SET):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        else:
            k = (pt_val - ct_val) % MOD
        if model == "A":
            residue = pt_pos % period
        else:
            residue = ct_pos % period
        residue_keys[residue].append(k)

    total = 0
    for keys in residue_keys.values():
        if len(keys) == 1:
            total += 1
        else:
            total += Counter(keys).most_common(1)[0][1]
    return total


def best_score_across_configs(inv_perm, periods, variants, models):
    """Best score across all period × variant × model configs."""
    best = 0
    best_cfg = None
    for p in periods:
        for v in variants:
            for m in models:
                s = strict_periodic_score(inv_perm, p, v, m)
                if s > best:
                    best = s
                    best_cfg = (p, v, m)
    return best, best_cfg


def score_at_period(inv_perm, period, variants, models):
    """Best score at a specific period across variants and models."""
    best = 0
    for v in variants:
        for m in models:
            s = strict_periodic_score(inv_perm, period, v, m)
            if s > best:
                best = s
    return best


def hamming_distance_from_identity(perm):
    """Number of positions where perm[i] != i."""
    return sum(1 for i in range(len(perm)) if perm[i] != i)


def random_swap(perm):
    """Return a copy of perm with two random positions swapped."""
    new_perm = list(perm)
    a, b = random.sample(range(len(perm)), 2)
    new_perm[a], new_perm[b] = new_perm[b], new_perm[a]
    return new_perm


def main():
    t0 = time.time()
    random.seed(42)
    variants = ["vigenere", "beaufort", "variant_beaufort"]
    models = ["A", "B"]
    periods = [2, 3, 4, 5, 6, 7]

    print("=" * 70)
    print("E-FRAC-33: Fitness Landscape Analysis")
    print("=" * 70)
    print()

    # ================================================================
    # Analysis 1: Parent-child score correlation
    # ================================================================
    print("--- Analysis 1: Parent-child score correlation ---")
    n_parents = 10000
    n_children = 5  # children per parent
    parent_scores = []
    child_scores = []
    delta_scores = []
    per_period_corr = {p: {"parent": [], "child": []} for p in periods}

    for i in range(n_parents):
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)
        p_score, _ = best_score_across_configs(inv, periods, variants, models)

        # Per-period scores
        for p in periods:
            ps = score_at_period(inv, p, variants, models)
            per_period_corr[p]["parent"].append(ps)

        for _ in range(n_children):
            child_perm = random_swap(perm)
            child_inv = invert_perm(child_perm)
            c_score, _ = best_score_across_configs(child_inv, periods, variants, models)
            parent_scores.append(p_score)
            child_scores.append(c_score)
            delta_scores.append(c_score - p_score)

            for p in periods:
                cs = score_at_period(child_inv, p, variants, models)
                per_period_corr[p]["child"].append(cs)

        if (i + 1) % 2000 == 0:
            print(f"  {i+1}/{n_parents} parents scored...")

    # Compute correlation
    n_pairs = len(parent_scores)
    mean_p = sum(parent_scores) / n_pairs
    mean_c = sum(child_scores) / n_pairs
    var_p = sum((x - mean_p) ** 2 for x in parent_scores) / n_pairs
    var_c = sum((x - mean_c) ** 2 for x in child_scores) / n_pairs
    cov_pc = sum((parent_scores[i] - mean_p) * (child_scores[i] - mean_c)
                 for i in range(n_pairs)) / n_pairs
    corr = cov_pc / (math.sqrt(var_p) * math.sqrt(var_c)) if var_p > 0 and var_c > 0 else 0

    mean_delta = sum(delta_scores) / len(delta_scores)
    delta_dist = Counter(delta_scores)

    print(f"\n  Parent-child pairs: {n_pairs}")
    print(f"  Parent mean: {mean_p:.3f}, Child mean: {mean_c:.3f}")
    print(f"  Correlation: {corr:.4f}")
    print(f"  Mean delta: {mean_delta:.4f}")
    print(f"  Delta distribution: {dict(sorted(delta_dist.items()))}")

    # Per-period correlations
    print("\n  Per-period parent-child correlations:")
    period_corrs = {}
    for p in periods:
        pp = per_period_corr[p]["parent"]
        cc = per_period_corr[p]["child"]
        n_pp = len(pp)
        mp = sum(pp) / n_pp
        mc = sum(cc) / n_pp
        vp = sum((x - mp) ** 2 for x in pp) / n_pp
        vc = sum((x - mc) ** 2 for x in cc) / n_pp
        cv = sum((pp[i] - mp) * (cc[i] - mc) for i in range(n_pp)) / n_pp
        r = cv / (math.sqrt(vp) * math.sqrt(vc)) if vp > 0 and vc > 0 else 0
        period_corrs[p] = round(r, 4)
        print(f"    Period {p}: r = {r:.4f}")

    # ================================================================
    # Analysis 2: Score autocorrelation over mutation chains
    # ================================================================
    print("\n--- Analysis 2: Mutation chain autocorrelation ---")
    n_chains = 100
    chain_length = 200
    lag_correlations = defaultdict(list)  # lag -> list of (score_t, score_{t+lag})

    for _ in range(n_chains):
        perm = list(range(N))
        random.shuffle(perm)
        scores = []
        for step in range(chain_length):
            inv = invert_perm(perm)
            s, _ = best_score_across_configs(inv, periods, variants, models)
            scores.append(s)
            perm = random_swap(perm)

        # Compute autocorrelation at various lags
        for lag in [1, 2, 5, 10, 20, 50, 100]:
            if lag < chain_length:
                for t in range(chain_length - lag):
                    lag_correlations[lag].append((scores[t], scores[t + lag]))

    print(f"  Chains: {n_chains}, length: {chain_length}")
    chain_autocorrs = {}
    for lag in sorted(lag_correlations.keys()):
        pairs = lag_correlations[lag]
        n_lp = len(pairs)
        xs = [p[0] for p in pairs]
        ys = [p[1] for p in pairs]
        mx = sum(xs) / n_lp
        my = sum(ys) / n_lp
        vx = sum((x - mx) ** 2 for x in xs) / n_lp
        vy = sum((y - my) ** 2 for y in ys) / n_lp
        cv = sum((xs[i] - mx) * (ys[i] - my) for i in range(n_lp)) / n_lp
        r = cv / (math.sqrt(vx) * math.sqrt(vy)) if vx > 0 and vy > 0 else 0
        chain_autocorrs[lag] = round(r, 4)
        print(f"  Lag {lag:3d}: r = {r:.4f} ({n_lp} pairs)")

    # ================================================================
    # Analysis 3: Hamming distance from identity vs score
    # ================================================================
    print("\n--- Analysis 3: Hamming distance from identity vs score ---")
    hamming_scores = defaultdict(list)

    # Sample permutations at various distances from identity
    for target_swaps in [1, 2, 3, 5, 10, 20, 50, 97]:
        n_samples_per = 1000
        for _ in range(n_samples_per):
            perm = list(range(N))
            for _ in range(target_swaps):
                a, b = random.sample(range(N), 2)
                perm[a], perm[b] = perm[b], perm[a]
            inv = invert_perm(perm)
            s, _ = best_score_across_configs(inv, periods, variants, models)
            h = hamming_distance_from_identity(perm)
            hamming_scores[target_swaps].append((h, s))

    print(f"  Swaps from identity: mean Hamming, mean score, max score")
    hamming_summary = {}
    for swaps in sorted(hamming_scores.keys()):
        data = hamming_scores[swaps]
        mean_h = sum(d[0] for d in data) / len(data)
        mean_s = sum(d[1] for d in data) / len(data)
        max_s = max(d[1] for d in data)
        hamming_summary[swaps] = {
            "mean_hamming": round(mean_h, 1),
            "mean_score": round(mean_s, 3),
            "max_score": max_s,
            "n_samples": len(data),
        }
        print(f"  {swaps:3d} swaps: Hamming={mean_h:.1f}, mean={mean_s:.3f}, max={max_s}/24")

    # ================================================================
    # Analysis 4: Hill-climbing simulation
    # ================================================================
    print("\n--- Analysis 4: Hill-climbing simulation ---")
    n_climbs = 100
    max_steps = 5000
    climb_results = []

    for _ in range(n_climbs):
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)
        current_score, current_cfg = best_score_across_configs(inv, periods, variants, models)

        best_seen = current_score
        steps_to_best = 0
        improvements = 0

        for step in range(max_steps):
            candidate = random_swap(perm)
            cand_inv = invert_perm(candidate)
            cand_score, cand_cfg = best_score_across_configs(cand_inv, periods, variants, models)

            if cand_score >= current_score:  # accept equal or better
                perm = candidate
                current_score = cand_score
                current_cfg = cand_cfg
                if cand_score > current_score:
                    improvements += 1
                if cand_score > best_seen:
                    best_seen = cand_score
                    steps_to_best = step + 1

        climb_results.append({
            "final_score": current_score,
            "best_seen": best_seen,
            "steps_to_best": steps_to_best,
            "improvements": improvements,
        })

    final_scores = [r["final_score"] for r in climb_results]
    best_seen_scores = [r["best_seen"] for r in climb_results]
    mean_final = sum(final_scores) / len(final_scores)
    max_final = max(final_scores)
    mean_best = sum(best_seen_scores) / len(best_seen_scores)
    max_best = max(best_seen_scores)
    final_dist = Counter(final_scores)
    best_dist = Counter(best_seen_scores)

    print(f"  Hill climbs: {n_climbs}, max steps: {max_steps}")
    print(f"  Final score: mean={mean_final:.2f}, max={max_final}/24")
    print(f"  Best seen: mean={mean_best:.2f}, max={max_best}/24")
    print(f"  Final score distribution: {dict(sorted(final_dist.items()))}")
    print(f"  Best seen distribution: {dict(sorted(best_dist.items()))}")

    # Compare to random sampling of same total evaluations
    n_random_equiv = n_climbs * max_steps  # 500K random samples
    print(f"\n  Equivalent random samples: {n_random_equiv}")
    random_max = 0
    random_score_dist = Counter()
    for _ in range(min(n_random_equiv, 100000)):  # cap at 100K for speed
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)
        s, _ = best_score_across_configs(inv, periods, variants, models)
        random_score_dist[s] += 1
        if s > random_max:
            random_max = s

    print(f"  Random max (from {min(n_random_equiv, 100000)} samples): {random_max}/24")

    # ================================================================
    # Analysis 5: Per-period score distributions for baseline reference
    # ================================================================
    print("\n--- Analysis 5: Per-period score distributions (10K random) ---")
    n_baseline = 10000
    per_period_dists = {p: Counter() for p in periods}

    for _ in range(n_baseline):
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)
        for p in periods:
            s = score_at_period(inv, p, variants, models)
            per_period_dists[p][s] += 1

    print(f"  Samples: {n_baseline}")
    period_stats = {}
    for p in periods:
        dist = per_period_dists[p]
        mean_s = sum(s * c for s, c in dist.items()) / n_baseline
        max_s = max(dist.keys())
        p99 = None
        cumulative = 0
        for s in sorted(dist.keys()):
            cumulative += dist[s]
            if cumulative >= 0.99 * n_baseline and p99 is None:
                p99 = s
        period_stats[p] = {"mean": round(mean_s, 3), "max": max_s, "p99": p99}
        print(f"  Period {p}: mean={mean_s:.3f}, max={max_s}, p99={p99}")

    # ================================================================
    # Summary and Verdict
    # ================================================================
    total_time = time.time() - t0
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Parent-child correlation (1 swap): {corr:.4f}")
    print(f"Chain autocorrelation at lag 1: {chain_autocorrs.get(1, 'N/A')}")
    print(f"Chain autocorrelation at lag 10: {chain_autocorrs.get(10, 'N/A')}")
    print(f"Chain autocorrelation at lag 50: {chain_autocorrs.get(50, 'N/A')}")
    print(f"Hill-climbing max (100 × 5K steps): {max_best}/24")
    print(f"Random max (100K samples): {random_max}/24")
    print(f"Hill-climbing advantage: {max_best - random_max} points")
    print()

    if corr < 0.3:
        landscape_verdict = "RUGGED"
        sa_verdict = "SA is unlikely to significantly outperform random search"
    elif corr < 0.6:
        landscape_verdict = "MODERATELY_SMOOTH"
        sa_verdict = "SA may provide modest advantage over random, but landscape is weak"
    else:
        landscape_verdict = "SMOOTH"
        sa_verdict = "SA should effectively navigate the landscape"

    print(f"Landscape: {landscape_verdict}")
    print(f"SA viability: {sa_verdict}")
    print(f"Total runtime: {total_time:.1f}s")

    # Save results
    out_dir = "results/frac"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "e_frac_33_fitness_landscape.json")

    output = {
        "experiment": "E-FRAC-33",
        "title": "Fitness Landscape Analysis of Permutation Space",
        "landscape_verdict": landscape_verdict,
        "sa_verdict": sa_verdict,
        "runtime_seconds": round(total_time, 1),
        "parent_child": {
            "n_pairs": n_pairs,
            "correlation": round(corr, 4),
            "mean_delta": round(mean_delta, 4),
            "delta_distribution": {str(k): v for k, v in sorted(delta_dist.items())},
        },
        "per_period_correlations": period_corrs,
        "chain_autocorrelation": chain_autocorrs,
        "hamming_vs_score": {str(k): v for k, v in hamming_summary.items()},
        "hill_climbing": {
            "n_climbs": n_climbs,
            "max_steps": max_steps,
            "mean_final": round(mean_final, 2),
            "max_final": max_final,
            "mean_best": round(mean_best, 2),
            "max_best": max_best,
            "final_distribution": {str(k): v for k, v in sorted(final_dist.items())},
            "best_distribution": {str(k): v for k, v in sorted(best_dist.items())},
        },
        "random_baseline": {
            "n_samples": min(n_random_equiv, 100000),
            "max_score": random_max,
        },
        "per_period_stats": period_stats,
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")
    print(f"\nRESULT: landscape={landscape_verdict} hill_climb_max={max_best}/24 "
          f"random_max={random_max}/24 verdict={sa_verdict}")


if __name__ == "__main__":
    main()
