#!/usr/bin/env python3
"""Null mask letter diversity across SA score tiers.

Cipher:   Analysis (null mask diversity)
Family:   analysis
Status:   active
Keyspace: 200 SA restarts × 300k steps, collecting all masks at score tiers
Last run:
Best score: N/A (diagnostic, not a decrypt attack)

QUESTION: Is the low letter diversity (7 distinct letters) of the consensus
null mask unique to the best SA solutions, or do most decent-scoring masks
show similar palette restriction?

The SA optimizer searches a huge space and returns the best mask. Comparing
that result against random draws isn't apples-to-apples. This test collects
ALL masks at various score tiers and measures palette diversity across them.

FOUR ANALYSES:
  1. Diversity distribution by score tier (8+ through 14+)
  2. Trajectory within single SA runs (does diversity decrease as score rises?)
  3. Random baseline (10,000 random masks, no optimization)
  4. Palette identity (among low-diversity masks, how many use the specific
     palette {B,G,I,K,O,W,Z} vs. some other 7-letter set?)
"""

import sys
import os
import random
import math
import time
import json
import collections
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

N_WORKERS = max(1, cpu_count() - 2)

from kryptos.kernel.constants import (
    CT, CRIB_POSITIONS, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
)

# ── Constants (copied from f_consensus_null_v1.py) ─────────────────────────

CT97 = CT
N = 97
N_NULLS = 24
N_PT = 73
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]
NC_SET = frozenset(NON_CRIB)

KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[c] for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']

# ── Cipher machinery (copied from f_consensus_null_v1.py) ──────────────────

def autokey_decrypt_ka(ct73_az, kw, beau=False):
    ct73_ka = [AZ_TO_KA[ci] for ci in ct73_az]
    kw_ka = [KA_IDX[c] for c in kw.upper() if c in KA_IDX]
    L = len(kw_ka)
    pt_ka_indices = []
    pt_output = []
    for i, cki in enumerate(ct73_ka):
        ki = kw_ka[i] if i < L else pt_ka_indices[i - L]
        pt_ki = ((ki - cki) if beau else (cki - ki)) % 26
        pt_ka_indices.append(pt_ki)
        pt_output.append(KA_STR[pt_ki])
    return ''.join(pt_output)


def count_crib_hits(pt, ene_s, bcl_s):
    e = sum(1 for j, c in enumerate(ENE_WORD) if ene_s + j < N_PT and pt[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD) if bcl_s + j < N_PT and pt[bcl_s + j] == c)
    return e + b, e, b


def score_kaka(null_set, kw='KRYPTOS', beau=False):
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c) - 65 for c in ct73]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2
    pt = autokey_decrypt_ka(ct73_az, kw, beau)
    total, _, _ = count_crib_hits(pt, ene_s, bcl_s)
    return float(total)


# ── Helpers ─────────────────────────────────────────────────────────────────

def distinct_at_mask(null_set):
    """Return (n_distinct, frozenset_of_letters) for CT letters at null positions."""
    letters = frozenset(CT97[p] for p in null_set)
    return len(letters), letters


def palette_fraction(null_set):
    """Fraction of null-position letters that are in the consensus palette."""
    return sum(1 for p in null_set if CT97[p] in NULL_PALETTE) / len(null_set)


# ── Modified SA: collects masks at all score tiers ──────────────────────────

THRESHOLDS = [8, 9, 10, 11, 12, 13, 14]


def sa_run_collecting(seed, steps=300_000, T0=0.5, max_per_tier=200,
                      trajectory_interval=5000):
    """SA that snapshots masks at every score threshold crossing.

    Returns dict with:
      - best_score, best_mask, best_n_distinct
      - collected: {threshold: [(n_distinct, letters_str), ...]}
      - trajectory: [(step, score, n_distinct), ...]
    """
    rng = random.Random(seed)
    pool = list(NON_CRIB)
    extra = set(rng.sample(pool, N_NULLS))
    null_set = set(extra)
    non_null = set(NC_SET - null_set)

    score = score_kaka(frozenset(null_set))
    best_sc = score
    best_null = frozenset(null_set)

    # Collection structures
    collected = {t: [] for t in THRESHOLDS}
    seen = {t: set() for t in THRESHOLDS}  # deduplicate by mask hash
    trajectory = []

    Tf = 0.01
    for step in range(steps):
        T = T0 * (Tf / T0) ** (step / steps)
        cands = list(null_set)
        if not cands or not non_null:
            break
        out = rng.choice(cands)
        into = rng.choice(list(non_null))
        null_set = (null_set - {out}) | {into}
        non_null = (non_null - {into}) | {out}
        new_sc = score_kaka(frozenset(null_set))
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / T):
            score = new_sc
            if score > best_sc:
                best_sc = score
                best_null = frozenset(null_set)

            # Collect at thresholds (only on accepted moves to avoid noise)
            mask_key = frozenset(null_set)
            for t in THRESHOLDS:
                if score >= t and len(collected[t]) < max_per_tier:
                    h = hash(mask_key)
                    if h not in seen[t]:
                        seen[t].add(h)
                        nd, letters = distinct_at_mask(mask_key)
                        collected[t].append((nd, ''.join(sorted(letters))))
        else:
            null_set = (null_set - {into}) | {out}
            non_null = (non_null - {out}) | {into}

        # Trajectory snapshot
        if step % trajectory_interval == 0:
            nd, _ = distinct_at_mask(frozenset(null_set))
            trajectory.append((step, int(score), nd))

    # Final snapshot
    nd_best, letters_best = distinct_at_mask(best_null)
    return {
        'seed': seed,
        'best_score': int(best_sc),
        'best_mask': sorted(best_null),
        'best_n_distinct': nd_best,
        'best_letters': ''.join(sorted(letters_best)),
        'collected': collected,
        'trajectory': trajectory,
    }


# ── Parallel worker ─────────────────────────────────────────────────────────

def _diversity_worker(seed):
    """Worker function for multiprocessing. Returns full collection result."""
    return sa_run_collecting(seed=seed, steps=300_000, T0=0.5)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

N_RESTARTS = 200

if __name__ == '__main__':

    print("=" * 70)
    print("NULL MASK DIVERSITY ANALYSIS")
    print("Question: Is low letter diversity unique to the best mask,")
    print("          or do most decent-scoring masks show it too?")
    print("=" * 70)
    print(f"CT97 = {CT97}")
    print(f"Consensus null positions: {sorted(CONSENSUS_NULL_POSITIONS)}")
    print(f"Consensus palette: {sorted(NULL_PALETTE)} ({len(NULL_PALETTE)} letters)")
    print(f"SA restarts: {N_RESTARTS}, steps: 300k, thresholds: {THRESHOLDS}")
    print(f"Workers: {N_WORKERS} (of {cpu_count()} cores)")
    print()

    t0 = time.time()

    # ── Phase 1: Run SA with collection (parallelized) ──────────────────────

    # Aggregation structures
    all_tier_data = {t: [] for t in THRESHOLDS}  # (n_distinct, letters_str)
    all_trajectories = []
    best_masks = []  # (score, n_distinct, letters)

    print("Phase 1: Running 200 SA restarts with mask collection...")
    print()

    seeds = [restart * 53 for restart in range(N_RESTARTS)]
    chunk_size = N_WORKERS * 2

    with Pool(processes=N_WORKERS) as mp_pool:
        for chunk_start in range(0, N_RESTARTS, chunk_size):
            chunk_seeds = seeds[chunk_start:chunk_start + chunk_size]
            results = mp_pool.map(_diversity_worker, chunk_seeds)

            for r in results:
                best_masks.append((r['best_score'], r['best_n_distinct'], r['best_letters']))
                for t in THRESHOLDS:
                    all_tier_data[t].extend(r['collected'][t])
                all_trajectories.append(r['trajectory'])

            elapsed = time.time() - t0
            done = chunk_start + len(chunk_seeds)
            total_collected = sum(len(all_tier_data[t]) for t in THRESHOLDS)
            last_r = results[-1]
            print(f"  done {done:3d}/{N_RESTARTS}: last_best={last_r['best_score']}/24 "
                  f"distinct={last_r['best_n_distinct']} letters={last_r['best_letters']} "
                  f"collected={total_collected} elapsed={elapsed:.0f}s")

    print()
    elapsed_phase1 = time.time() - t0
    print(f"Phase 1 complete: {elapsed_phase1:.0f}s")
    print()

    # ── Analysis 1: Diversity by score tier ─────────────────────────────────

    print("=" * 70)
    print("ANALYSIS 1: Letter diversity by score tier")
    print("=" * 70)
    print()
    print(f"{'Tier':>6} | {'N_masks':>8} | {'Mean':>6} | {'Median':>6} | "
          f"{'≤7':>6} | {'frac≤7':>8} | {'≤10':>6} | {'frac≤10':>8} | "
          f"{'Min':>4} | {'Max':>4}")
    print("-" * 90)

    tier_summary = {}
    for t in THRESHOLDS:
        data = all_tier_data[t]
        n = len(data)
        if n == 0:
            print(f"  {t:>4}+ | {'(none)':>8}")
            tier_summary[str(t)] = {"n_masks": 0}
            continue
        diversities = [d[0] for d in data]
        diversities.sort()
        mean_d = sum(diversities) / n
        median_d = diversities[n // 2]
        le7 = sum(1 for d in diversities if d <= 7)
        le10 = sum(1 for d in diversities if d <= 10)
        min_d = min(diversities)
        max_d = max(diversities)

        print(f"  {t:>4}+ | {n:>8} | {mean_d:>6.1f} | {median_d:>6} | "
              f"{le7:>6} | {le7/n:>8.4f} | {le10:>6} | {le10/n:>8.4f} | "
              f"{min_d:>4} | {max_d:>4}")

        tier_summary[str(t)] = {
            "n_masks": n,
            "mean_distinct": round(mean_d, 2),
            "median_distinct": median_d,
            "n_le7": le7,
            "frac_le7": round(le7 / n, 6),
            "n_le10": le10,
            "frac_le10": round(le10 / n, 6),
            "min_distinct": min_d,
            "max_distinct": max_d,
        }

    print()

    # ── Analysis 1b: Best-mask diversity distribution ───────────────────────

    print("Best-mask diversity across all restarts:")
    best_diversities = [b[1] for b in best_masks]
    best_scores = [b[0] for b in best_masks]
    for nd in range(min(best_diversities), max(best_diversities) + 1):
        count = sum(1 for d in best_diversities if d == nd)
        if count > 0:
            bar = '#' * (count * 40 // N_RESTARTS)
            print(f"  {nd:2d} distinct: {count:4d}/{N_RESTARTS} ({count*100/N_RESTARTS:5.1f}%) {bar}")
    print()

    # ── Analysis 2: Trajectory (diversity vs score) ────────────────────────

    print("=" * 70)
    print("ANALYSIS 2: Trajectory — does diversity decrease as score improves?")
    print("=" * 70)
    print()

    score_to_diversities = collections.defaultdict(list)
    for traj in all_trajectories:
        for step, score, n_dist in traj:
            score_to_diversities[score].append(n_dist)

    print(f"{'Score':>6} | {'N_obs':>8} | {'Mean div':>9} | {'Std div':>8} | {'Min':>4} | {'Max':>4}")
    print("-" * 55)

    trajectory_summary = {}
    for score in sorted(score_to_diversities.keys()):
        divs = score_to_diversities[score]
        n = len(divs)
        mean_d = sum(divs) / n
        variance = sum((d - mean_d) ** 2 for d in divs) / n if n > 1 else 0
        std_d = variance ** 0.5
        print(f"  {score:>4}  | {n:>8} | {mean_d:>9.2f} | {std_d:>8.2f} | {min(divs):>4} | {max(divs):>4}")
        trajectory_summary[str(score)] = {
            "n_obs": n,
            "mean_diversity": round(mean_d, 3),
            "std_diversity": round(std_d, 3),
            "min": min(divs),
            "max": max(divs),
        }

    # Compute correlation between score and diversity
    all_pairs = []
    for traj in all_trajectories:
        for step, score, n_dist in traj:
            all_pairs.append((score, n_dist))

    if len(all_pairs) > 2:
        mean_s = sum(p[0] for p in all_pairs) / len(all_pairs)
        mean_d = sum(p[1] for p in all_pairs) / len(all_pairs)
        cov = sum((p[0] - mean_s) * (p[1] - mean_d) for p in all_pairs) / len(all_pairs)
        var_s = sum((p[0] - mean_s) ** 2 for p in all_pairs) / len(all_pairs)
        var_d = sum((p[1] - mean_d) ** 2 for p in all_pairs) / len(all_pairs)
        if var_s > 0 and var_d > 0:
            corr = cov / (var_s ** 0.5 * var_d ** 0.5)
        else:
            corr = 0.0
        print(f"\nScore-diversity correlation (Pearson r): {corr:.4f}")
        print(f"  Negative = optimizer drives toward low diversity")
        print(f"  Near zero = diversity is independent of score")
        print(f"  Positive = higher scores have MORE diversity")
    else:
        corr = 0.0

    print()

    # ── Analysis 3: Random baseline ────────────────────────────────────────

    print("=" * 70)
    print("ANALYSIS 3: Random baseline (no optimization)")
    print("=" * 70)
    print()

    N_RANDOM = 10_000
    rng_baseline = random.Random(42)
    random_diversities = []
    for _ in range(N_RANDOM):
        mask = frozenset(rng_baseline.sample(NON_CRIB, N_NULLS))
        nd, _ = distinct_at_mask(mask)
        random_diversities.append(nd)

    random_diversities.sort()
    mean_rand = sum(random_diversities) / N_RANDOM
    le7_rand = sum(1 for d in random_diversities if d <= 7)

    print(f"Random 24-position masks from non-crib pool ({N_RANDOM} samples):")
    print(f"  Mean distinct: {mean_rand:.2f}")
    print(f"  Frac ≤7: {le7_rand}/{N_RANDOM} = {le7_rand/N_RANDOM:.6f}")
    print(f"  Percentile of 7: {le7_rand * 100 / N_RANDOM:.3f}%")
    print()

    # Distribution histogram
    print("  Distribution:")
    for nd in range(min(random_diversities), max(random_diversities) + 1):
        count = sum(1 for d in random_diversities if d == nd)
        if count > 0:
            bar = '#' * (count * 50 // max(1, max(collections.Counter(random_diversities).values())))
            print(f"    {nd:2d} distinct: {count:5d}/{N_RANDOM} ({count*100/N_RANDOM:5.2f}%) {bar}")
    print()

    random_baseline = {
        "n_samples": N_RANDOM,
        "mean_distinct": round(mean_rand, 3),
        "frac_le7": round(le7_rand / N_RANDOM, 6),
        "percentile_7": round(le7_rand * 100 / N_RANDOM, 4),
    }

    # ── Analysis 4: Palette identity ───────────────────────────────────────

    print("=" * 70)
    print("ANALYSIS 4: Among low-diversity masks, how many use the specific")
    print(f"            palette {sorted(NULL_PALETTE)}?")
    print("=" * 70)
    print()

    palette_analysis = {}
    for t in THRESHOLDS:
        data = all_tier_data[t]
        if not data:
            continue
        low_div = [(nd, letters) for nd, letters in data if nd <= 7]
        if not low_div:
            print(f"  Tier {t}+: no masks with ≤7 distinct letters")
            palette_analysis[str(t)] = {"n_low_div": 0}
            continue

        exact_palette = sum(1 for _, letters in low_div
                            if set(letters) == NULL_PALETTE)
        subset_palette = sum(1 for _, letters in low_div
                             if set(letters) <= NULL_PALETTE)

        # Also compute palette fraction for ALL masks at this tier
        all_pf = []
        for nd, letters in data:
            pf = sum(1 for c in letters if c in NULL_PALETTE) / len(letters)
            all_pf.append(pf)
        mean_pf = sum(all_pf) / len(all_pf)

        print(f"  Tier {t}+: {len(low_div)} masks with ≤7 distinct")
        print(f"    Exact palette match: {exact_palette}/{len(low_div)} "
              f"({exact_palette*100/len(low_div):.1f}%)")
        print(f"    Subset of palette:   {subset_palette}/{len(low_div)} "
              f"({subset_palette*100/len(low_div):.1f}%)")
        print(f"    Mean palette fraction (all masks at tier): {mean_pf:.3f}")
        print()

        # Show the actual letter sets found
        letter_sets = collections.Counter(letters for _, letters in low_div)
        print(f"    Distinct letter sets found:")
        for ls, count in letter_sets.most_common(10):
            marker = " ← CONSENSUS" if set(ls) == NULL_PALETTE else ""
            print(f"      {{{ls}}}: {count}x{marker}")
        print()

        palette_analysis[str(t)] = {
            "n_low_div": len(low_div),
            "exact_palette": exact_palette,
            "subset_palette": subset_palette,
            "mean_palette_frac_all": round(mean_pf, 4),
        }

    # ── Verdict ─────────────────────────────────────────────────────────────

    print("=" * 70)
    print("VERDICT")
    print("=" * 70)
    print()

    decision_tier = "13" if tier_summary.get("13", {}).get("n_masks", 0) > 10 else "12"
    dt = tier_summary.get(decision_tier, {})
    frac_le7 = dt.get("frac_le7", -1)

    if frac_le7 < 0 or dt.get("n_masks", 0) < 10:
        verdict = "INSUFFICIENT_DATA"
        verdict_text = ("Not enough masks collected at the decision tier to draw "
                        "conclusions. Try more restarts or lower thresholds.")
    elif frac_le7 > 0.5:
        verdict = "LOW_DIVERSITY_IS_GENERIC"
        verdict_text = (f"At tier {decision_tier}+, {frac_le7*100:.1f}% of masks have ≤7 "
                        f"distinct letters. The SA optimizer inherently drives toward "
                        f"palette restriction. The p=6.3e-5 claim is an artifact of "
                        f"comparing optimized output against random draws.")
    elif frac_le7 > 0.1:
        verdict = "LOW_DIVERSITY_IS_ENRICHED"
        verdict_text = (f"At tier {decision_tier}+, {frac_le7*100:.1f}% of masks have ≤7 "
                        f"distinct letters. Low diversity is more common at high scores "
                        f"than the random baseline ({random_baseline['frac_le7']*100:.3f}%), "
                        f"but not universal. The p-value needs recalibration against "
                        f"the SA-conditioned distribution, not random draws.")
    else:
        verdict = "LOW_DIVERSITY_IS_RARE"
        verdict_text = (f"At tier {decision_tier}+, only {frac_le7*100:.1f}% of masks have "
                        f"≤7 distinct letters. The consensus mask's palette restriction "
                        f"is unusual even among high-scoring masks. This strengthens "
                        f"the steganographic hypothesis.")

    # Add trajectory interpretation
    if abs(corr) < 0.05:
        traj_text = (f"Score-diversity correlation is near zero (r={corr:.4f}). "
                     f"The optimizer does not systematically drive toward low diversity.")
    elif corr < -0.05:
        traj_text = (f"Score-diversity correlation is negative (r={corr:.4f}). "
                     f"The optimizer has a bias toward low diversity at higher scores. "
                     f"This partially explains the palette restriction.")
    else:
        traj_text = (f"Score-diversity correlation is positive (r={corr:.4f}). "
                     f"Higher scores actually have MORE diversity — the low-diversity "
                     f"consensus mask is genuinely anomalous.")

    print(f"Decision tier: {decision_tier}+")
    print(f"Verdict: {verdict}")
    print(f"  {verdict_text}")
    print()
    print(f"Trajectory: {traj_text}")
    print()

    # ── Save results ────────────────────────────────────────────────────────

    out_path = os.path.join(_ROOT, "results", "null_mask_diversity_01.json")
    result = {
        "experiment": "null_mask_diversity_01",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "parameters": {
            "n_restarts": N_RESTARTS,
            "sa_steps": 300_000,
            "T0": 0.5,
            "thresholds": THRESHOLDS,
            "max_per_tier": 200,
            "trajectory_interval": 5000,
            "workers": N_WORKERS,
        },
        "tier_summary": tier_summary,
        "trajectory_by_score": trajectory_summary,
        "score_diversity_correlation": round(corr, 4),
        "random_baseline": random_baseline,
        "palette_analysis": palette_analysis,
        "best_mask_diversities": {
            "mean": round(sum(best_diversities) / len(best_diversities), 2),
            "distribution": dict(collections.Counter(best_diversities)),
        },
        "verdict": verdict,
        "verdict_text": verdict_text,
        "trajectory_text": traj_text,
    }

    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"Results saved to {out_path}")

    elapsed_total = time.time() - t0
    print(f"\nTotal elapsed: {elapsed_total:.0f}s ({elapsed_total/60:.1f} min)")

    print("\nverdict:", json.dumps({
        "verdict_status": verdict,
        "summary": verdict_text[:200],
        "score_diversity_corr": round(corr, 4),
        "decision_tier": decision_tier,
    }))
