#!/usr/bin/env python3
"""E-S-108: Column Statistics for Transposition Ordering Identification.

HYPOTHESIS: If K4 uses width-7 columnar transposition (Model B: trans→sub),
the correct column ordering should produce columns with detectable statistical
regularities in the CT, even through the substitution layer.

Key insight: If the substitution is position-dependent (varying by column),
different columns will have DIFFERENT frequency distributions. But if the
column ordering is WRONG, the frequency signatures get scrambled.

Metrics per ordering:
1. Inter-column IC variance: correct ordering should show structured variance
2. Column-pair chi-squared: adjacent columns may show different distributions
3. Differential digram analysis: consecutive-row letter pairs within columns
4. Per-column entropy: columns with structured substitution should have non-uniform entropy
5. Lag-7 preservation: correct ordering should maximize lag-7 autocorrelation
6. Composite score: weighted combination of all metrics

Also tests:
- Z-score of each metric across all 5040 orderings
- Cross-metric agreement (orderings in top-50 for multiple metrics)

Output: results/e_s_108_column_statistics.json
"""
import json
import math
import time
import sys
import os
from itertools import permutations
from collections import Counter

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
N = CT_LEN
WIDTH = 7
NROWS = N // WIDTH  # 13
EXTRA = N % WIDTH   # 6


def build_columnar_perm(order):
    """Build columnar perm: perm[ct_pos] = pt_pos (gather)."""
    w = len(order)
    nf = N // w
    extra = N % w
    heights = [nf + (1 if c < extra else 0) for c in range(w)]
    perm = []
    for rank in range(w):
        col = order[rank]
        for row in range(heights[col]):
            perm.append(row * w + col)
    return perm


def arrange_into_grid(ct_indices, order):
    """Arrange CT into a grid using the given column ordering.

    For Model B (trans→sub): CT was produced by:
    1. Writing PT into rows of width 7
    2. Reading columns in 'order' sequence → intermediate
    3. Applying substitution → CT

    To analyze, we reverse the column reading:
    The CT values at positions corresponding to each column group
    came from the same column in the original PT grid.
    """
    heights = [NROWS + (1 if c < EXTRA else 0) for c in range(WIDTH)]

    # Build column groups: which CT positions belong to which original column
    col_groups = {}  # original_col → list of CT values
    pos = 0
    for rank in range(WIDTH):
        col = order[rank]
        h = heights[col]
        col_groups[col] = [ct_indices[pos + i] for i in range(h)]
        pos += h

    return col_groups


def column_ic(values):
    """Compute IC of a list of letter indices."""
    n = len(values)
    if n <= 1:
        return 0.0
    freq = Counter(values)
    total = sum(f * (f - 1) for f in freq.values())
    return total / (n * (n - 1))


def column_entropy(values):
    """Compute Shannon entropy of letter distribution."""
    n = len(values)
    if n == 0:
        return 0.0
    freq = Counter(values)
    ent = 0.0
    for f in freq.values():
        p = f / n
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def column_pair_chi2(col_a, col_b):
    """Chi-squared test for whether two columns have the same distribution."""
    freq_a = Counter(col_a)
    freq_b = Counter(col_b)
    all_vals = set(freq_a.keys()) | set(freq_b.keys())
    n_a = len(col_a)
    n_b = len(col_b)
    if n_a == 0 or n_b == 0:
        return 0.0
    chi2 = 0.0
    for v in all_vals:
        o_a = freq_a.get(v, 0)
        o_b = freq_b.get(v, 0)
        e_a = (o_a + o_b) * n_a / (n_a + n_b)
        e_b = (o_a + o_b) * n_b / (n_a + n_b)
        if e_a > 0:
            chi2 += (o_a - e_a) ** 2 / e_a
        if e_b > 0:
            chi2 += (o_b - e_b) ** 2 / e_b
    return chi2


def within_column_digrams(col_values):
    """Count repeated consecutive-row letter pairs within a column."""
    repeats = 0
    for i in range(len(col_values) - 1):
        if col_values[i] == col_values[i + 1]:
            repeats += 1
    return repeats


def lag7_score(ct_indices):
    """Count lag-7 matches in the given sequence."""
    matches = 0
    for i in range(len(ct_indices) - 7):
        if ct_indices[i] == ct_indices[i + 7]:
            matches += 1
    return matches


def differential_ic(ct_indices, perm):
    """IC of (CT[i] - CT[perm[i]]) mod 26 at consecutive transposed positions."""
    diffs = []
    inv_perm = [0] * len(perm)
    for i, p in enumerate(perm):
        inv_perm[p] = i

    for i in range(len(ct_indices) - 1):
        # Consecutive positions in the plaintext grid
        pt_pos_a = i
        pt_pos_b = i + 1
        # Where do they end up in CT?
        ct_pos_a = inv_perm[pt_pos_a]
        ct_pos_b = inv_perm[pt_pos_b]
        if ct_pos_a < len(ct_indices) and ct_pos_b < len(ct_indices):
            diff = (ct_indices[ct_pos_a] - ct_indices[ct_pos_b]) % MOD
            diffs.append(diff)

    if len(diffs) < 2:
        return 0.0
    freq = Counter(diffs)
    n = len(diffs)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


print("=" * 70)
print("E-S-108: Column Statistics for Transposition Ordering Identification")
print("=" * 70)
t0 = time.time()

results = {}

# Compute all metrics for all 5040 orderings
print("Computing metrics for all 5040 w7 orderings...", flush=True)

all_metrics = []

for i, order in enumerate(permutations(range(WIDTH))):
    order = list(order)
    col_groups = arrange_into_grid(CT_IDX, order)
    perm = build_columnar_perm(order)

    # Metric 1: IC variance across columns
    ics = [column_ic(col_groups[c]) for c in range(WIDTH)]
    ic_mean = sum(ics) / WIDTH
    ic_var = sum((ic - ic_mean) ** 2 for ic in ics) / WIDTH

    # Metric 2: Sum of pairwise column chi-squared
    chi2_sum = 0.0
    n_pairs = 0
    for a in range(WIDTH):
        for b in range(a + 1, WIDTH):
            chi2_sum += column_pair_chi2(col_groups[a], col_groups[b])
            n_pairs += 1
    chi2_mean = chi2_sum / n_pairs if n_pairs > 0 else 0.0

    # Metric 3: Within-column repeated digrams (should be low for structured sub)
    total_repeats = sum(within_column_digrams(col_groups[c]) for c in range(WIDTH))

    # Metric 4: Entropy variance
    entropies = [column_entropy(col_groups[c]) for c in range(WIDTH)]
    ent_mean = sum(entropies) / WIDTH
    ent_var = sum((e - ent_mean) ** 2 for e in entropies) / WIDTH

    # Metric 5: Differential IC (consecutive PT positions)
    diff_ic = differential_ic(CT_IDX, perm)

    # Metric 6: Mean column IC (higher = more structured within each column)
    mean_ic = ic_mean

    # Metric 7: Max single-column IC
    max_ic = max(ics)

    all_metrics.append({
        "order": order,
        "ic_var": ic_var,
        "chi2_mean": chi2_mean,
        "total_repeats": total_repeats,
        "ent_var": ent_var,
        "diff_ic": diff_ic,
        "mean_ic": mean_ic,
        "max_ic": max_ic,
    })

    if (i + 1) % 1000 == 0:
        print(f"  {i+1}/5040...", flush=True)

print(f"All metrics computed in {time.time()-t0:.1f}s")

# Compute z-scores for each metric
metric_names = ["ic_var", "chi2_mean", "total_repeats", "ent_var", "diff_ic", "mean_ic", "max_ic"]

for mname in metric_names:
    vals = [m[mname] for m in all_metrics]
    mean_v = sum(vals) / len(vals)
    std_v = (sum((v - mean_v) ** 2 for v in vals) / len(vals)) ** 0.5
    if std_v > 0:
        for m in all_metrics:
            m[f"{mname}_z"] = (m[mname] - mean_v) / std_v
    else:
        for m in all_metrics:
            m[f"{mname}_z"] = 0.0

# Find top orderings for each metric
print("\n--- Top orderings per metric ---")
top_per_metric = {}

for mname in metric_names:
    # Sort by z-score (descending for most metrics, ascending for some)
    # Higher diff_ic, mean_ic, max_ic, ic_var → more structure
    # Higher chi2_mean → columns more different from each other
    # Higher ent_var → more variation in column entropy
    # Lower total_repeats might indicate structure... or higher?
    sorted_by = sorted(all_metrics, key=lambda m: m[f"{mname}_z"], reverse=True)
    top5 = sorted_by[:5]
    bot5 = sorted_by[-5:]

    print(f"\n  {mname}:")
    print(f"    Top 5 (highest z):")
    for t in top5:
        print(f"      order={t['order']}, z={t[f'{mname}_z']:.3f}, val={t[mname]:.6f}")

    top_per_metric[mname] = {
        "top50_orders": [m["order"] for m in sorted_by[:50]],
        "top5": [{"order": m["order"], "z": round(m[f"{mname}_z"], 3),
                  "val": round(m[mname], 6)} for m in top5],
    }

# Cross-metric agreement: find orderings in top-50 for 3+ metrics
print("\n--- Cross-metric agreement (top-50 for 3+ metrics) ---")
order_counts = Counter()
for mname in metric_names:
    for order in top_per_metric[mname]["top50_orders"]:
        order_counts[tuple(order)] += 1

multi_metric = [(order, count) for order, count in order_counts.items() if count >= 3]
multi_metric.sort(key=lambda x: -x[1])

print(f"Orderings in top-50 for 3+ metrics: {len(multi_metric)}")
for order, count in multi_metric[:15]:
    print(f"  {list(order)}: {count}/{len(metric_names)} metrics")
    # Show the metric values for this ordering
    for m in all_metrics:
        if tuple(m["order"]) == order:
            details = ", ".join(f"{mn}={m[f'{mn}_z']:.2f}" for mn in metric_names)
            print(f"    z-scores: {details}")
            break

results["cross_metric_3plus"] = [{"order": list(o), "count": c} for o, c in multi_metric[:30]]

# Also check for 4+ and 5+ agreement
for threshold in [4, 5, 6]:
    n_agree = sum(1 for _, c in multi_metric if c >= threshold)
    print(f"  In top-50 for {threshold}+ metrics: {n_agree}")
    results[f"cross_metric_{threshold}plus"] = n_agree

# Special check: does any known-keyword ordering appear in the top lists?
KNOWN_KEYWORD_ORDERS = {
    "KRYPTOS": tuple(sorted(range(7), key=lambda i: ("KRYPTOS"[i], i))),
    "PALIMPS": tuple(sorted(range(7), key=lambda i: ("PALIMPS"[i], i))),
    "ABSCISS": tuple(sorted(range(7), key=lambda i: ("ABSCISS"[i], i))),
    "BERLINN": tuple(sorted(range(7), key=lambda i: ("BERLINK"[i], i))),  # BERLIN + padding
    "SHADOWS": tuple(sorted(range(7), key=lambda i: ("SHADOWS"[i], i))),
}

print("\n--- Known keyword ordering positions ---")
for kw_name, kw_order in KNOWN_KEYWORD_ORDERS.items():
    for mname in metric_names:
        sorted_by = sorted(all_metrics, key=lambda m: m[f"{mname}_z"], reverse=True)
        for rank, m in enumerate(sorted_by):
            if tuple(m["order"]) == kw_order:
                if rank < 100:
                    print(f"  {kw_name} order {list(kw_order)}: {mname} rank={rank+1}/{len(all_metrics)}")
                break

# E-S-101 top ordering: [5,3,0,4,1,2,6] (diff IC z=3.97)
es101_order = (5, 3, 0, 4, 1, 2, 6)
print(f"\n--- E-S-101 top ordering {list(es101_order)} ---")
for m in all_metrics:
    if tuple(m["order"]) == es101_order:
        for mname in metric_names:
            sorted_by = sorted(all_metrics, key=lambda mm: mm[f"{mname}_z"], reverse=True)
            for rank, mm in enumerate(sorted_by):
                if tuple(mm["order"]) == es101_order:
                    print(f"  {mname}: rank={rank+1}/5040, z={mm[f'{mname}_z']:.3f}")
                    break
        break

# ===========================================================================
# Phase 2: For top-ranked orderings, analyze the implied substitution
# ===========================================================================
print("\n--- Phase 2: Substitution analysis for top orderings ---")

# Get orderings that appear in 3+ top-50 lists
top_orders = [order for order, count in multi_metric[:10]]

for order_tuple in top_orders:
    order = list(order_tuple)
    col_groups = arrange_into_grid(CT_IDX, order)
    perm = build_columnar_perm(order)
    inv_perm = [0] * len(perm)
    for i, p in enumerate(perm):
        inv_perm[p] = i

    # At crib positions, derive substitution mapping
    # Model B: CT[ct_pos] = sub(PT[pt_pos], param)
    # where pt_pos = perm[ct_pos]
    sub_mapping = {}  # (pt_letter, column) → ct_letter
    for pt_pos in sorted(CRIB_POSITIONS):
        ct_pos = inv_perm[pt_pos]
        col = pt_pos % WIDTH
        pt_letter = ALPH[CRIB_DICT[pt_pos] if isinstance(CRIB_DICT[pt_pos], int)
                          else ALPH_IDX[CRIB_DICT[pt_pos]]]
        # CRIB_DICT maps pos→char
        pt_char = CRIB_DICT[pt_pos]
        ct_char = CT[ct_pos]
        key = (pt_char, col)
        if key in sub_mapping:
            if sub_mapping[key] != ct_char:
                pass  # Inconsistency noted
        else:
            sub_mapping[key] = ct_char

    # Check for patterns in the substitution
    print(f"\n  Order {order}:")
    # Group by column
    for col in range(WIDTH):
        col_entries = [(pt, ct) for (pt, c), ct in sub_mapping.items() if c == col]
        if col_entries:
            print(f"    Col {col}: {col_entries}")

# ===========================================================================
# Summary
# ===========================================================================
elapsed = time.time() - t0

print(f"\n{'='*70}")
print(f"E-S-108 COMPLETE — elapsed: {elapsed:.1f}s")
if multi_metric:
    best_order, best_count = multi_metric[0]
    print(f"Best cross-metric ordering: {list(best_order)} ({best_count}/{len(metric_names)} metrics)")
print(f"{'='*70}")

results["metric_summaries"] = {
    mname: {"top5": top_per_metric[mname]["top5"]}
    for mname in metric_names
}
results["elapsed_seconds"] = elapsed

os.makedirs("results", exist_ok=True)
with open("results/e_s_108_column_statistics.json", "w") as f:
    json.dump({"experiment": "E-S-108",
               "description": "Column statistics for ordering identification",
               "results": results}, f, indent=2, default=str)

print(f"\nResults saved to results/e_s_108_column_statistics.json")
