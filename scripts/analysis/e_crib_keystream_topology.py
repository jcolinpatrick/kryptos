#!/usr/bin/env python3
"""
e_crib_keystream_topology.py — Crib keystream topology analysis

Tests 5 statistical hypotheses about the Beaufort A=0 keystream at crib positions:
  1. Boundary sharpness at BCL position 71 (7/8 palette + 0/3 split)
  2. Key segment length hypothesis (palette runs from crib starts)
  3. ENE K-repeat significance (K appears 4/6 in last 6 of ENE)
  4. Symmetric enrichment pattern (two disjoint enriched clusters)
  5. K-value dominance (repeated palette letters at both cribs)

ID:     e_crib_keystream_topology
FAMILY: analysis
STATUS: active
"""

import sys
import os
import json
import random
from collections import Counter
from datetime import datetime, timezone
from math import comb, log10

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT

# --- Constants ---
PALETTE = set("BGIKOWZ")
N_TRIALS = 100_000
random.seed(20260325)

# Cribs: ENE = EASTNORTHEAST at 21-33, BCL = BERLINCLOCK at 63-73
ENE_PT = "EASTNORTHEAST"
BCL_PT = "BERLINCLOCK"
ENE_START, ENE_END = 21, 33  # inclusive
BCL_START, BCL_END = 63, 73  # inclusive

def beaufort_key(ct_char, pt_char):
    """Beaufort A=0: k = (CT + PT) mod 26"""
    return (ord(ct_char) - 65 + ord(pt_char) - 65) % 26

def key_to_letter(k):
    return chr(k + 65)

# Compute keystream at all 24 crib positions
ene_ks = [key_to_letter(beaufort_key(CT[ENE_START + i], ENE_PT[i])) for i in range(len(ENE_PT))]
bcl_ks = [key_to_letter(beaufort_key(CT[BCL_START + i], BCL_PT[i])) for i in range(len(BCL_PT))]
all_ks = ene_ks + bcl_ks  # 24 values in positional order

print("=" * 72)
print("CRIB KEYSTREAM TOPOLOGY ANALYSIS")
print("=" * 72)
print(f"ENE keystream (pos 21-33): {''.join(ene_ks)}")
print(f"BCL keystream (pos 63-73): {''.join(bcl_ks)}")
print(f"Palette: {sorted(PALETTE)}")
print(f"ENE palette count: {sum(1 for c in ene_ks if c in PALETTE)}/13")
print(f"BCL palette count: {sum(1 for c in bcl_ks if c in PALETTE)}/11")
print(f"Combined: {sum(1 for c in all_ks if c in PALETTE)}/24")
print()

results = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "script": "e_crib_keystream_topology",
    "ciphertext": CT,
    "ene_keystream": "".join(ene_ks),
    "bcl_keystream": "".join(bcl_ks),
    "palette": sorted(PALETTE),
    "tests": {}
}

# =====================================================================
# TEST 1: Boundary sharpness at BCL position 71
# =====================================================================
print("-" * 72)
print("TEST 1: Boundary sharpness at BCL position 71")
print("-" * 72)

bcl_palette_flags = [1 if c in PALETTE else 0 for c in bcl_ks]
n_bcl = len(bcl_ks)  # 11

# For every contiguous window of size w, compute palette density
print("\nWindow analysis (BCL keystream, 11 positions):")
print(f"  Position:  {'  '.join(str(63+i) for i in range(n_bcl))}")
print(f"  Letter:    {'  '.join(bcl_ks)}")
print(f"  Palette:   {'  '.join(str(f) for f in bcl_palette_flags)}")
print()

best_windows = {}
for w in range(1, n_bcl + 1):
    best_count = 0
    best_start = 0
    for start in range(n_bcl - w + 1):
        count = sum(bcl_palette_flags[start:start + w])
        if count > best_count:
            best_count = count
            best_start = start
    best_windows[w] = (best_start, best_count)
    if w in [3, 5, 7, 8, 10, 11]:
        print(f"  Window size {w:2d}: best = {best_count}/{w} starting at offset {best_start} (pos {63+best_start})")

# Monte Carlo: P(any window of size 8 has >=7 palette AND remaining 3 has 0 palette)
# in 11 random draws from 26 letters (7/26 are palette)
p_palette = 7.0 / 26.0
split_count = 0
any_8_ge7_count = 0
for _ in range(N_TRIALS):
    draws = [1 if random.random() < p_palette else 0 for _ in range(11)]
    found_8ge7 = False
    found_split = False
    for start in range(11 - 8 + 1):  # windows of size 8
        window = draws[start:start + 8]
        if sum(window) >= 7:
            found_8ge7 = True
            # Check remaining 3
            remaining = draws[:start] + draws[start + 8:]
            if sum(remaining) == 0:
                found_split = True
                break
    if found_8ge7:
        any_8_ge7_count += 1
    if found_split:
        split_count += 1

p_any_8ge7 = any_8_ge7_count / N_TRIALS
p_split = split_count / N_TRIALS

print(f"\nMonte Carlo ({N_TRIALS:,} trials, p_palette={p_palette:.4f}):")
print(f"  P(any window of 8 has >=7 palette): {p_any_8ge7:.6f} ({any_8_ge7_count}/{N_TRIALS})")
print(f"  P(7/8 in some window AND 0/3 in remainder): {p_split:.6f} ({split_count}/{N_TRIALS})")
print(f"  Observed: 7/8 in pos 63-70, 0/3 in pos 71-73 => split IS present")

# Also test: P(first 8 specifically have >=7) AND (last 3 specifically have 0)
exact_split_count = 0
for _ in range(N_TRIALS):
    draws = [1 if random.random() < p_palette else 0 for _ in range(11)]
    if sum(draws[:8]) >= 7 and sum(draws[8:]) == 0:
        exact_split_count += 1
p_exact_split = exact_split_count / N_TRIALS

print(f"  P(first 8 have >=7 AND last 3 have 0): {p_exact_split:.6f} ({exact_split_count}/{N_TRIALS})")

results["tests"]["T1_boundary_sharpness"] = {
    "description": "BCL position 71 boundary: 7/8 palette in pos 63-70, 0/3 in pos 71-73",
    "bcl_keystream": "".join(bcl_ks),
    "palette_flags": bcl_palette_flags,
    "window_analysis": {str(w): {"best_start": s, "best_count": c} for w, (s, c) in best_windows.items()},
    "mc_trials": N_TRIALS,
    "p_any_8_window_ge7": p_any_8ge7,
    "p_7of8_and_0of3_any_position": p_split,
    "p_first8_ge7_and_last3_eq0": p_exact_split,
    "verdict": "SIGNIFICANT" if p_split < 0.005 else "NOT_SIGNIFICANT"
}

# =====================================================================
# TEST 2: Key segment length hypothesis
# =====================================================================
print()
print("-" * 72)
print("TEST 2: Key segment length hypothesis")
print("-" * 72)

print("\nPalette runs from crib starts:")
print("  (counting consecutive palette values from position start)")

# BCL: start at pos 63
bcl_runs = {}
for L in range(4, 14):
    # Strict: how many consecutive palette from start
    strict_run = 0
    for i in range(min(L, n_bcl)):
        if bcl_palette_flags[i]:
            strict_run += 1
        else:
            break
    # Tolerant: at most 1 non-palette in first L positions
    window = bcl_palette_flags[:min(L, n_bcl)]
    tolerant_count = sum(window)
    non_palette_in_window = len(window) - tolerant_count
    bcl_runs[L] = {
        "strict_run_from_start": strict_run,
        "palette_in_first_L": tolerant_count,
        "non_palette_in_first_L": non_palette_in_window,
        "window_size": len(window)
    }

print("\n  BCL (from pos 63):")
print(f"  {'L':>3s} | {'Strict run':>10s} | {'Palette/L':>10s} | {'Non-pal':>7s}")
print(f"  {'-'*3}-+-{'-'*10}-+-{'-'*10}-+-{'-'*7}")
for L in range(4, 14):
    r = bcl_runs[L]
    print(f"  {L:3d} | {r['strict_run_from_start']:10d} | {r['palette_in_first_L']}/{r['window_size']:<8d} | {r['non_palette_in_first_L']:7d}")

# Note: BCL starts with O (palette) at pos 63, but pos 64 = C (non-palette)
# So strict run from start = 1. But pos 63,65,66,67,68,69,70 are all palette.
# The run from pos 65 is 6 consecutive palette letters.
print(f"\n  BCL note: pos 64 (C) breaks the run. Run from pos 65: {sum(bcl_palette_flags[2:8])} consecutive palette (pos 65-70)")

# ENE: start at pos 21
ene_palette_flags = [1 if c in PALETTE else 0 for c in ene_ks]
ene_runs = {}
for L in range(4, 14):
    strict_run = 0
    for i in range(min(L, len(ene_ks))):
        if ene_palette_flags[i]:
            strict_run += 1
        else:
            break
    window = ene_palette_flags[:min(L, len(ene_ks))]
    tolerant_count = sum(window)
    non_palette_in_window = len(window) - tolerant_count
    ene_runs[L] = {
        "strict_run_from_start": strict_run,
        "palette_in_first_L": tolerant_count,
        "non_palette_in_first_L": non_palette_in_window,
        "window_size": len(window)
    }

print("\n  ENE (from pos 21):")
print(f"  {'L':>3s} | {'Strict run':>10s} | {'Palette/L':>10s} | {'Non-pal':>7s}")
print(f"  {'-'*3}-+-{'-'*10}-+-{'-'*10}-+-{'-'*7}")
for L in range(4, 14):
    r = ene_runs[L]
    print(f"  {L:3d} | {r['strict_run_from_start']:10d} | {r['palette_in_first_L']}/{r['window_size']:<8d} | {r['non_palette_in_first_L']:7d}")

# ENE back-loaded: check runs ending at pos 33
print(f"\n  ENE back-loaded analysis (from end):")
for L in [4, 5, 6, 7, 8]:
    window = ene_palette_flags[-L:]
    pal = sum(window)
    print(f"    Last {L} positions: {pal}/{L} palette ({''.join(ene_ks[-L:])})")

results["tests"]["T2_key_segment_length"] = {
    "description": "Key segment length: palette runs from crib starts for L=4..13",
    "bcl_runs": bcl_runs,
    "ene_runs": ene_runs,
    "bcl_note": "pos 64 (C) breaks strict run; 6 consecutive palette at pos 65-70",
    "ene_note": "ENE enrichment is back-loaded: last 6 have 4/6 palette (KUKKKL)"
}

# =====================================================================
# TEST 3: ENE K-repeat significance
# =====================================================================
print()
print("-" * 72)
print("TEST 3: ENE K-repeat significance")
print("-" * 72)

ene_str = "".join(ene_ks)
print(f"\nENE keystream: {ene_str}")
ene_counts = Counter(ene_ks)
print(f"Letter frequencies: {dict(ene_counts)}")
print(f"K appears {ene_counts['K']} times total, positions: {[21+i for i, c in enumerate(ene_ks) if c == 'K']}")
last6 = ene_ks[-6:]
print(f"Last 6 values: {''.join(last6)}")
last6_counts = Counter(last6)
print(f"Last 6 frequencies: {dict(last6_counts)}")
print(f"K in last 6: {last6_counts['K']}")

# MC: P(any value appears >=4 times in last 6 of 13 random draws from 26)
any_ge4_last6 = 0
any_ge4_last6_palette = 0
for _ in range(N_TRIALS):
    draws = [random.randint(0, 25) for _ in range(13)]
    last6_trial = draws[-6:]
    counts = Counter(last6_trial)
    max_count = max(counts.values())
    if max_count >= 4:
        any_ge4_last6 += 1
        # Check if the dominant value is a palette letter
        for val, cnt in counts.items():
            if cnt >= 4 and chr(val + 65) in PALETTE:
                any_ge4_last6_palette += 1
                break

p_any_ge4 = any_ge4_last6 / N_TRIALS
p_any_ge4_palette = any_ge4_last6_palette / N_TRIALS

# Exact: P(specific value appears >=4 in 6 draws from 26)
from math import factorial
def binom_pmf(n, k, p):
    return comb(n, k) * (p ** k) * ((1 - p) ** (n - k))

p_specific_ge4_in_6 = sum(binom_pmf(6, k, 1/26) for k in range(4, 7))

print(f"\nExact P(specific letter appears >=4/6): {p_specific_ge4_in_6:.2e}")
print(f"Monte Carlo ({N_TRIALS:,} trials):")
print(f"  P(ANY letter appears >=4 in last 6 of 13): {p_any_ge4:.6f} ({any_ge4_last6}/{N_TRIALS})")
print(f"  P(ANY palette letter appears >=4 in last 6): {p_any_ge4_palette:.6f} ({any_ge4_last6_palette}/{N_TRIALS})")

# Also: K appears 4 times in positions 28,30,31,32 (0-indexed within ENE: 7,9,10,11)
# That's 4 out of the last 7 positions (indices 6-12)
last7 = ene_ks[-7:]
print(f"\nLast 7 values: {''.join(last7)} — K count: {Counter(last7)['K']}")

results["tests"]["T3_ene_k_repeat"] = {
    "description": "K appears 4 times in last 6 of ENE keystream",
    "ene_keystream": ene_str,
    "k_positions_absolute": [21 + i for i, c in enumerate(ene_ks) if c == 'K'],
    "k_count_total": ene_counts['K'],
    "k_count_last6": last6_counts['K'],
    "p_specific_ge4_in_6_exact": p_specific_ge4_in_6,
    "p_any_ge4_last6_mc": p_any_ge4,
    "p_any_palette_ge4_last6_mc": p_any_ge4_palette,
    "verdict": "SIGNIFICANT" if p_any_ge4_palette < 0.005 else "NOTABLE" if p_any_ge4_palette < 0.05 else "NOT_SIGNIFICANT"
}

# =====================================================================
# TEST 4: Symmetric enrichment pattern (two disjoint clusters)
# =====================================================================
print()
print("-" * 72)
print("TEST 4: Symmetric enrichment pattern")
print("-" * 72)

# All 24 crib keystream values in a single sequence
# ENE: indices 0-12, BCL: indices 13-23
all_palette_flags = [1 if c in PALETTE else 0 for c in all_ks]
print(f"\nAll 24 crib keystream values: {''.join(all_ks)}")
print(f"Palette flags: {''.join(str(f) for f in all_palette_flags)}")
print(f"Total palette: {sum(all_palette_flags)}/24")

# Find best two-cluster partition
# Cluster 1: contiguous sub-run of length a, Cluster 2: contiguous sub-run of length b
# Both disjoint. Maximize (palette_in_c1/a + palette_in_c2/b)
# Or: maximize sum of palette counts in two disjoint windows that match observed pattern
# Observed: ENE last 6 have 4/6 palette, BCL first 8 have 7/8 palette

# Simple approach: for all pairs of disjoint contiguous windows, compute combined palette count
best_two_cluster = None
best_metric = 0
n_all = len(all_ks)  # 24

for a_start in range(n_all):
    for a_len in range(4, min(9, n_all - a_start + 1)):
        a_end = a_start + a_len
        a_pal = sum(all_palette_flags[a_start:a_end])
        for b_start in range(a_end, n_all):
            for b_len in range(4, min(9, n_all - b_start + 1)):
                b_end = b_start + b_len
                b_pal = sum(all_palette_flags[b_start:b_end])
                # Metric: combined density
                metric = a_pal / a_len + b_pal / b_len
                if metric > best_metric:
                    best_metric = metric
                    best_two_cluster = (a_start, a_len, a_pal, b_start, b_len, b_pal)

if best_two_cluster:
    a_s, a_l, a_p, b_s, b_l, b_p = best_two_cluster
    print(f"\nBest two disjoint windows (size 4-8):")
    print(f"  Window 1: indices {a_s}-{a_s+a_l-1} ({a_p}/{a_l} palette) = {''.join(all_ks[a_s:a_s+a_l])}")
    print(f"  Window 2: indices {b_s}-{b_s+b_l-1} ({b_p}/{b_l} palette) = {''.join(all_ks[b_s:b_s+b_l])}")
    print(f"  Combined density metric: {best_metric:.4f}")

# Monte Carlo: P(13/24 palette values cluster into two disjoint windows achieving >=7/8 + >=4/6)
observed_cluster_metric = 7/8 + 4/6  # = 0.875 + 0.667 = 1.542
cluster_count = 0
for _ in range(N_TRIALS):
    flags = [1 if random.random() < p_palette else 0 for _ in range(24)]
    total_pal = sum(flags)
    # Find best two-cluster metric
    trial_best = 0
    for a_s in range(24):
        for a_l in range(4, min(9, 24 - a_s + 1)):
            a_e = a_s + a_l
            a_p = sum(flags[a_s:a_e])
            for b_s in range(a_e, 24):
                for b_l in range(4, min(9, 24 - b_s + 1)):
                    b_e = b_s + b_l
                    b_p = sum(flags[b_s:b_e])
                    m = a_p / a_l + b_p / b_l
                    if m > trial_best:
                        trial_best = m
    if trial_best >= observed_cluster_metric:
        cluster_count += 1

p_cluster = cluster_count / N_TRIALS

print(f"\nMonte Carlo ({N_TRIALS:,} trials):")
print(f"  Observed combined density: {observed_cluster_metric:.4f}")
print(f"  P(two disjoint windows achieve >= {observed_cluster_metric:.4f}): {p_cluster:.6f} ({cluster_count}/{N_TRIALS})")

# Alternate metric: P(some window of 8 has >=7 AND some disjoint window of 6 has >=4)
specific_count = 0
for _ in range(N_TRIALS):
    flags = [1 if random.random() < p_palette else 0 for _ in range(24)]
    found = False
    for a_s in range(24 - 8 + 1):
        if sum(flags[a_s:a_s+8]) >= 7:
            for b_s in range(24 - 6 + 1):
                if b_s + 6 <= a_s or b_s >= a_s + 8:  # disjoint
                    if sum(flags[b_s:b_s+6]) >= 4:
                        found = True
                        break
        if found:
            break
    if found:
        specific_count += 1

p_specific_cluster = specific_count / N_TRIALS
print(f"  P(any 8-window >=7 AND any disjoint 6-window >=4): {p_specific_cluster:.6f} ({specific_count}/{N_TRIALS})")

# Gap analysis
print(f"\nGap between enriched regions:")
print(f"  BCL enrichment: pos 63-70 (8 positions)")
print(f"  ENE enrichment: pos 27-32 (6 positions)")
print(f"  Gap: 63 - 32 = 31 positions (unknown keystream)")

results["tests"]["T4_symmetric_enrichment"] = {
    "description": "Two disjoint enriched clusters in crib keystream",
    "all_keystream": "".join(all_ks),
    "total_palette": sum(all_palette_flags),
    "best_two_cluster": {
        "window1": {"start_idx": best_two_cluster[0], "length": best_two_cluster[1], "palette": best_two_cluster[2]} if best_two_cluster else None,
        "window2": {"start_idx": best_two_cluster[3], "length": best_two_cluster[4], "palette": best_two_cluster[5]} if best_two_cluster else None,
        "metric": best_metric
    },
    "observed_cluster_density": observed_cluster_metric,
    "p_cluster_density_mc": p_cluster,
    "p_8ge7_and_6ge4_disjoint_mc": p_specific_cluster,
    "gap_positions": 31,
    "verdict": "SIGNIFICANT" if p_specific_cluster < 0.005 else "NOTABLE" if p_specific_cluster < 0.05 else "NOT_SIGNIFICANT"
}

# =====================================================================
# TEST 5: K-value dominance at ENE + G-value dominance at BCL
# =====================================================================
print()
print("-" * 72)
print("TEST 5: K-value and G-value dominance")
print("-" * 72)

# ENE: K appears 4/13 times (positions 28, 30, 31, 32)
# BCL: G appears 3/11 times (positions 65, 66, 68)
# Both K and G are palette letters

print(f"\nENE letter counts: {dict(Counter(ene_ks))}")
print(f"BCL letter counts: {dict(Counter(bcl_ks))}")

# P(specific letter >=4/13)
p_k_ge4_in_13 = sum(binom_pmf(13, k, 1/26) for k in range(4, 14))
print(f"\nExact P(specific letter appears >=4/13): {p_k_ge4_in_13:.2e}")

# P(specific letter >=3/11)
p_g_ge3_in_11 = sum(binom_pmf(11, k, 1/26) for k in range(3, 12))
print(f"Exact P(specific letter appears >=3/11): {p_g_ge3_in_11:.2e}")

# Combined: P(some palette letter >=4/13 in ENE AND some palette letter >=3/11 in BCL)
joint_dom_count = 0
ene_dom_count = 0
bcl_dom_count = 0
for _ in range(N_TRIALS):
    ene_trial = [random.randint(0, 25) for _ in range(13)]
    bcl_trial = [random.randint(0, 25) for _ in range(11)]

    ene_counts_trial = Counter(ene_trial)
    bcl_counts_trial = Counter(bcl_trial)

    ene_has_dom = any(ene_counts_trial[v] >= 4 and chr(v + 65) in PALETTE for v in range(26))
    bcl_has_dom = any(bcl_counts_trial[v] >= 3 and chr(v + 65) in PALETTE for v in range(26))

    if ene_has_dom:
        ene_dom_count += 1
    if bcl_has_dom:
        bcl_dom_count += 1
    if ene_has_dom and bcl_has_dom:
        joint_dom_count += 1

p_ene_dom = ene_dom_count / N_TRIALS
p_bcl_dom = bcl_dom_count / N_TRIALS
p_joint_dom = joint_dom_count / N_TRIALS
p_independent = p_ene_dom * p_bcl_dom

print(f"\nMonte Carlo ({N_TRIALS:,} trials):")
print(f"  P(palette letter >=4/13 in ENE): {p_ene_dom:.6f}")
print(f"  P(palette letter >=3/11 in BCL): {p_bcl_dom:.6f}")
print(f"  P(both): {p_joint_dom:.6f}")
print(f"  P(independent product): {p_independent:.6f}")
print(f"  Ratio (joint/independent): {p_joint_dom/p_independent:.3f}" if p_independent > 0 else "  N/A")

# Also: K at ENE has 4 consecutive-ish appearances (pos 28,30,31,32)
# What's P(a specific letter appears at 4 specific positions out of 13)?
# = (1/26)^4 * (25/26)^9 * C(13,4) ... but positions are not specific a priori
# Better: what's P(any letter has a run of >=3 consecutive in the keystream of length 13)?
consec_count = 0
for _ in range(N_TRIALS):
    draws = [random.randint(0, 25) for _ in range(13)]
    has_run3 = False
    for i in range(len(draws) - 2):
        if draws[i] == draws[i+1] == draws[i+2]:
            has_run3 = True
            break
    if has_run3:
        consec_count += 1

p_run3 = consec_count / N_TRIALS
print(f"\n  P(any run of >=3 identical in 13 draws): {p_run3:.6f}")
print(f"  ENE has KKK at positions 30-32 (3 consecutive K's)")

# K at positions 28,30,31,32 = 4 K's in last 6 positions
# What about a run of 3 consecutive identical that are ALSO palette?
consec_pal_count = 0
for _ in range(N_TRIALS):
    draws = [random.randint(0, 25) for _ in range(13)]
    has_run3_pal = False
    for i in range(len(draws) - 2):
        if draws[i] == draws[i+1] == draws[i+2] and chr(draws[i] + 65) in PALETTE:
            has_run3_pal = True
            break
    if has_run3_pal:
        consec_pal_count += 1

p_run3_pal = consec_pal_count / N_TRIALS
print(f"  P(run of >=3 identical PALETTE letters in 13 draws): {p_run3_pal:.6f}")

results["tests"]["T5_value_dominance"] = {
    "description": "Dominant palette letters: K=4/13 in ENE, G=3/11 in BCL",
    "ene_dominant": {"letter": "K", "count": ene_counts['K'], "total": 13},
    "bcl_dominant": {"letter": "G", "count": Counter(bcl_ks)['G'], "total": 11},
    "p_K_ge4_in_13_exact": p_k_ge4_in_13,
    "p_G_ge3_in_11_exact": p_g_ge3_in_11,
    "p_ene_palette_dominant_mc": p_ene_dom,
    "p_bcl_palette_dominant_mc": p_bcl_dom,
    "p_joint_dominant_mc": p_joint_dom,
    "p_independent_product": p_independent,
    "p_run3_any_mc": p_run3,
    "p_run3_palette_mc": p_run3_pal,
    "ene_has_KKK_consecutive": True,
    "verdict": "SIGNIFICANT" if p_joint_dom < 0.005 else "NOTABLE" if p_joint_dom < 0.05 else "NOT_SIGNIFICANT"
}

# =====================================================================
# SUMMARY
# =====================================================================
print()
print("=" * 72)
print("SUMMARY")
print("=" * 72)

verdicts = {name: t.get("verdict", "N/A") for name, t in results["tests"].items()}
for name, v in verdicts.items():
    desc = results["tests"][name]["description"]
    print(f"  {name}: {v}")
    print(f"    {desc}")

# Key p-values summary
print(f"\nKey p-values:")
t1 = results["tests"]["T1_boundary_sharpness"]
print(f"  T1 BCL 7/8+0/3 split (any position): {t1['p_7of8_and_0of3_any_position']:.6f}")
print(f"  T1 BCL 7/8+0/3 split (exact position): {t1['p_first8_ge7_and_last3_eq0']:.6f}")
t3 = results["tests"]["T3_ene_k_repeat"]
print(f"  T3 K>=4/6 in last 6 (any palette): {t3['p_any_palette_ge4_last6_mc']:.6f}")
t4 = results["tests"]["T4_symmetric_enrichment"]
print(f"  T4 Two-cluster (8>=7 AND 6>=4): {t4['p_8ge7_and_6ge4_disjoint_mc']:.6f}")
t5 = results["tests"]["T5_value_dominance"]
print(f"  T5 Joint palette dominance: {t5['p_joint_dominant_mc']:.6f}")
print(f"  T5 Consecutive run of 3 palette: {t5['p_run3_palette_mc']:.6f}")

# Save results
results_path = os.path.join(_ROOT, "results", "crib_keystream_topology.json")
with open(results_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to: {results_path}")
