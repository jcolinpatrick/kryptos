#!/usr/bin/env python3
"""E-CHART-08: False positive rate analysis for w9 + 2-char insertion scores.

Context: E-CHART-07 found 10/24 crib score inserting "YR" at position 61,
then w9 columnar transposition with order [0,5,7,6,3,4,1,8,2].
This script determines whether 10/24 is statistically significant.

Three tests:
  A) Random baseline: random 2-char pairs at random positions, exhaustive w9.
     Measures P(max_score >= 10 | random insertion + all 9! orderings).
  B) Position 61 specificity: all 676 letter pairs at pos 61 with the
     specific ordering [0,5,7,6,3,4,1,8,2].
  C) Ordering specificity: YR@61 with 10K random orderings vs random pair
     at random position with 10K random orderings.
"""
import json, itertools, os, random, sys, time
from collections import Counter

from kryptos.kernel.constants import CT, CT_LEN, ALPH, CRIB_DICT, N_CRIBS

random.seed(42)

def columnar_decrypt(ct, width, order):
    """Decrypt columnar transposition. order[i] = which column is read i-th."""
    n = len(ct)
    nrows = (n + width - 1) // width
    ncols = width
    n_long = n - (nrows - 1) * ncols
    if n % ncols == 0:
        n_long = ncols

    col_lens = [0] * ncols
    for col in range(ncols):
        col_lens[col] = nrows if col < n_long else nrows - 1

    cols = {}
    pos = 0
    for rank in range(ncols):
        col_idx = order[rank]
        length = col_lens[col_idx]
        cols[col_idx] = ct[pos:pos + length]
        pos += length

    result = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(cols.get(col, '')):
                result.append(cols[col][row])
    return ''.join(result)


def quick_crib_score(pt):
    """Fast crib scoring."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == ch:
            matches += 1
    return matches


def insert_and_decrypt(ct, c1, c2, insert_pos, order):
    """Insert two chars at insert_pos, then columnar decrypt at width 9.
    Returns the max crib score testing both the 99-char PT and the PT
    with inserted chars removed (to recover 97-char alignment)."""
    extended = ct[:insert_pos] + c1 + c2 + ct[insert_pos:]
    pt_full = columnar_decrypt(extended, 9, order)

    # Score full 99-char PT (cribs at same absolute positions)
    sc99 = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_full) and pt_full[pos] == ch:
            sc99 += 1

    # Score with inserted chars removed from PT
    pt_removed = pt_full[:insert_pos] + pt_full[insert_pos + 2:]
    sc97 = quick_crib_score(pt_removed)

    return max(sc99, sc97)


print("=" * 70)
print("E-CHART-08: Noise Analysis for W9 + 2-Char Insertion")
print("=" * 70)
sys.stdout.flush()

t0 = time.time()
results = {}

# ── Test A: Random baseline — exhaustive w9 orderings ──
# For each random config: insert random 2-letter pair at random position,
# test ALL 362,880 w9 orderings, record the maximum score.
# This gives the distribution of max scores under H0.
#
# 50 samples × 362,880 = 18.1M checks — feasible.

N_RANDOM_SAMPLES = 50
ALL_ORDERINGS = list(itertools.permutations(range(9)))  # 362,880

print(f"\n--- Test A: Random baseline ({N_RANDOM_SAMPLES} samples × {len(ALL_ORDERINGS)} orderings) ---")
sys.stdout.flush()

max_scores_random = []
score_distributions_random = []

for trial in range(N_RANDOM_SAMPLES):
    c1 = ALPH[random.randint(0, 25)]
    c2 = ALPH[random.randint(0, 25)]
    insert_pos = random.randint(0, CT_LEN)  # 0 to 97 inclusive

    trial_max = 0
    trial_dist = Counter()

    for order in ALL_ORDERINGS:
        sc = insert_and_decrypt(CT, c1, c2, insert_pos, list(order))
        trial_dist[sc] += 1
        if sc > trial_max:
            trial_max = sc

    max_scores_random.append(trial_max)
    score_distributions_random.append(dict(trial_dist))

    elapsed = time.time() - t0
    rate = (trial + 1) * len(ALL_ORDERINGS) / elapsed
    eta = (N_RANDOM_SAMPLES - trial - 1) * len(ALL_ORDERINGS) / rate if rate > 0 else 0
    print(f"  Trial {trial+1}/{N_RANDOM_SAMPLES}: {c1}{c2}@{insert_pos} → max={trial_max}/24  "
          f"[{elapsed:.0f}s elapsed, {rate:.0f} configs/s, ETA {eta:.0f}s]")
    sys.stdout.flush()

# Compute statistics
max_score_counter = Counter(max_scores_random)
mean_max = sum(max_scores_random) / len(max_scores_random)
sorted_maxes = sorted(max_scores_random)
median_max = sorted_maxes[len(sorted_maxes) // 2]
p_ge_10 = sum(1 for s in max_scores_random if s >= 10) / len(max_scores_random)
p_ge_11 = sum(1 for s in max_scores_random if s >= 11) / len(max_scores_random)
p_ge_9 = sum(1 for s in max_scores_random if s >= 9) / len(max_scores_random)

print(f"\n  Test A Results ({N_RANDOM_SAMPLES} random configs, exhaustive w9 orderings):")
print(f"    Mean max score: {mean_max:.2f}/24")
print(f"    Median max score: {median_max}/24")
print(f"    Max score distribution: {dict(sorted(max_score_counter.items()))}")
print(f"    P(max >= 9):  {p_ge_9:.3f} ({sum(1 for s in max_scores_random if s >= 9)}/{N_RANDOM_SAMPLES})")
print(f"    P(max >= 10): {p_ge_10:.3f} ({sum(1 for s in max_scores_random if s >= 10)}/{N_RANDOM_SAMPLES})")
print(f"    P(max >= 11): {p_ge_11:.3f} ({sum(1 for s in max_scores_random if s >= 11)}/{N_RANDOM_SAMPLES})")
sys.stdout.flush()

results['test_a'] = {
    'n_samples': N_RANDOM_SAMPLES,
    'n_orderings': len(ALL_ORDERINGS),
    'max_scores': max_scores_random,
    'mean_max': mean_max,
    'median_max': median_max,
    'p_ge_9': p_ge_9,
    'p_ge_10': p_ge_10,
    'p_ge_11': p_ge_11,
    'distribution': dict(max_score_counter),
}


# ── Test B: Position 61 specificity ──
# All 676 two-letter pairs (AA..ZZ) at position 61, with the specific
# ordering [0,5,7,6,3,4,1,8,2]. If most pairs score high, it's the
# ordering that's overfitting, not YR specifically.

SPECIFIC_ORDER = [0, 5, 7, 6, 3, 4, 1, 8, 2]

print(f"\n--- Test B: All 676 letter pairs at pos 61, order={SPECIFIC_ORDER} ---")
sys.stdout.flush()

pair_scores_b = {}
score_counter_b = Counter()

for i, c1 in enumerate(ALPH):
    for c2 in ALPH:
        sc = insert_and_decrypt(CT, c1, c2, 61, SPECIFIC_ORDER)
        pair_scores_b[c1 + c2] = sc
        score_counter_b[sc] += 1

# Sort by score
top_pairs = sorted(pair_scores_b.items(), key=lambda x: -x[1])[:20]
yr_score = pair_scores_b.get('YR', 0)
mean_score_b = sum(pair_scores_b.values()) / len(pair_scores_b)
n_ge_10 = sum(1 for s in pair_scores_b.values() if s >= 10)

print(f"  Mean score: {mean_score_b:.2f}/24")
print(f"  Score distribution: {dict(sorted(score_counter_b.items()))}")
print(f"  Pairs scoring >= 10: {n_ge_10}/676 ({100*n_ge_10/676:.1f}%)")
print(f"  YR score: {yr_score}/24")
print(f"  Top 20 pairs: {top_pairs}")
sys.stdout.flush()

results['test_b'] = {
    'position': 61,
    'order': SPECIFIC_ORDER,
    'mean_score': mean_score_b,
    'yr_score': yr_score,
    'n_ge_10': n_ge_10,
    'distribution': dict(score_counter_b),
    'top_20': top_pairs,
}


# ── Test C: Ordering specificity ──
# Part 1: YR at position 61 with 10K random orderings
# Part 2: Random 2-letter pair at random position with 10K random orderings
# Compare fraction scoring >= 10

N_RANDOM_ORDERS = 10000

print(f"\n--- Test C: Ordering specificity ({N_RANDOM_ORDERS} random orderings) ---")
sys.stdout.flush()

# Part C1: YR@61, random orderings
scores_c1 = []
order_pool = list(range(9))
for _ in range(N_RANDOM_ORDERS):
    order = random.sample(order_pool, 9)
    sc = insert_and_decrypt(CT, 'Y', 'R', 61, order)
    scores_c1.append(sc)

c1_counter = Counter(scores_c1)
c1_ge_10 = sum(1 for s in scores_c1 if s >= 10)
c1_mean = sum(scores_c1) / len(scores_c1)

print(f"  C1: YR@61, {N_RANDOM_ORDERS} random orderings:")
print(f"    Mean: {c1_mean:.3f}, P(>=10): {c1_ge_10}/{N_RANDOM_ORDERS} = {c1_ge_10/N_RANDOM_ORDERS:.5f}")
print(f"    Distribution: {dict(sorted(c1_counter.items()))}")

# Part C2: Random pair at random position, random orderings
scores_c2 = []
for _ in range(N_RANDOM_ORDERS):
    c1 = ALPH[random.randint(0, 25)]
    c2 = ALPH[random.randint(0, 25)]
    insert_pos = random.randint(0, CT_LEN)
    order = random.sample(order_pool, 9)
    sc = insert_and_decrypt(CT, c1, c2, insert_pos, order)
    scores_c2.append(sc)

c2_counter = Counter(scores_c2)
c2_ge_10 = sum(1 for s in scores_c2 if s >= 10)
c2_mean = sum(scores_c2) / len(scores_c2)

print(f"  C2: Random pair@random pos, {N_RANDOM_ORDERS} random orderings:")
print(f"    Mean: {c2_mean:.3f}, P(>=10): {c2_ge_10}/{N_RANDOM_ORDERS} = {c2_ge_10/N_RANDOM_ORDERS:.5f}")
print(f"    Distribution: {dict(sorted(c2_counter.items()))}")

# Part C3: YR@61 with the specific ordering score (reference)
yr_specific = insert_and_decrypt(CT, 'Y', 'R', 61, SPECIFIC_ORDER)
print(f"  Reference: YR@61 + order {SPECIFIC_ORDER} = {yr_specific}/24")
sys.stdout.flush()

results['test_c'] = {
    'c1_yr_at_61': {
        'n': N_RANDOM_ORDERS,
        'mean': c1_mean,
        'p_ge_10': c1_ge_10 / N_RANDOM_ORDERS,
        'distribution': dict(c1_counter),
    },
    'c2_random_all': {
        'n': N_RANDOM_ORDERS,
        'mean': c2_mean,
        'p_ge_10': c2_ge_10 / N_RANDOM_ORDERS,
        'distribution': dict(c2_counter),
    },
    'yr_specific_score': yr_specific,
}


# ── Test D (bonus): Exhaustive w9 on K4 WITHOUT insertion ──
# What's the max score for plain w9 transposition on the 97-char CT?
# This gives us the "no insertion" baseline.

print(f"\n--- Test D: Pure w9 transposition (no insertion), all {len(ALL_ORDERINGS)} orderings ---")
sys.stdout.flush()

max_score_no_insert = 0
best_order_no_insert = None
score_counter_d = Counter()

for order in ALL_ORDERINGS:
    pt = columnar_decrypt(CT, 9, list(order))
    sc = quick_crib_score(pt)
    score_counter_d[sc] += 1
    if sc > max_score_no_insert:
        max_score_no_insert = sc
        best_order_no_insert = list(order)

d_ge_10 = sum(v for k, v in score_counter_d.items() if k >= 10)
d_mean = sum(k * v for k, v in score_counter_d.items()) / sum(score_counter_d.values())

print(f"  Max score: {max_score_no_insert}/24 (order={best_order_no_insert})")
print(f"  Mean score: {d_mean:.3f}")
print(f"  Orderings scoring >= 10: {d_ge_10}/{len(ALL_ORDERINGS)}")
print(f"  Distribution: {dict(sorted(score_counter_d.items()))}")
sys.stdout.flush()

results['test_d'] = {
    'max_score': max_score_no_insert,
    'best_order': best_order_no_insert,
    'mean_score': d_mean,
    'n_ge_10': d_ge_10,
    'distribution': dict(score_counter_d),
}


# ── Summary ──
elapsed = time.time() - t0
print(f"\n{'=' * 70}")
print(f"E-CHART-08: SUMMARY")
print(f"{'=' * 70}")
print(f"Elapsed: {elapsed:.1f}s")
print()
print(f"Test A — Random insertion + exhaustive w9 ({N_RANDOM_SAMPLES} trials):")
print(f"  Mean max score: {mean_max:.2f}")
print(f"  P(max >= 10): {p_ge_10:.3f}")
print(f"  P(max >= 11): {p_ge_11:.3f}")
print(f"  Interpretation: If P(max>=10) is high, 10/24 is a FALSE POSITIVE.")
print()
print(f"Test B — All 676 pairs at pos 61, specific ordering:")
print(f"  Mean: {mean_score_b:.2f}, pairs >= 10: {n_ge_10}/676")
print(f"  YR score: {yr_score}/24")
print(f"  Interpretation: If many pairs score high, the ordering is overfitting.")
print()
print(f"Test C — Ordering specificity:")
print(f"  YR@61 + random orderings:   mean={c1_mean:.3f}, P(>=10)={c1_ge_10/N_RANDOM_ORDERS:.5f}")
print(f"  Random+random orderings:    mean={c2_mean:.3f}, P(>=10)={c2_ge_10/N_RANDOM_ORDERS:.5f}")
print()
print(f"Test D — Pure w9 (no insertion, 97 chars):")
print(f"  Max score: {max_score_no_insert}/24, Mean: {d_mean:.3f}")
print()

# Overall assessment
if p_ge_10 >= 0.5:
    verdict = "DEFINITE FALSE POSITIVE: majority of random configs achieve 10+/24"
elif p_ge_10 >= 0.1:
    verdict = "LIKELY FALSE POSITIVE: >10% of random configs achieve 10+/24"
elif p_ge_10 >= 0.01:
    verdict = "MARGINALLY SIGNIFICANT: 1-10% false positive rate, still likely noise"
else:
    verdict = "POTENTIALLY SIGNIFICANT: <1% false positive rate, warrants investigation"

print(f"VERDICT: {verdict}")
print(f"{'=' * 70}")

results['summary'] = {
    'elapsed_s': elapsed,
    'verdict': verdict,
    'e_chart_07_score': 10,
    'e_chart_07_config': {'pair': 'YR', 'pos': 61, 'order': SPECIFIC_ORDER},
}

os.makedirs('results', exist_ok=True)
with open('results/e_chart_08_noise.json', 'w') as f:
    json.dump(results, f, indent=2)
print(f"Artifact: results/e_chart_08_noise.json")
