#!/usr/bin/env python3
"""
E-ENRICHMENT-TOPOLOGY: Joint ENE+BCL Enrichment Topology Across Mask Variations

Tests whether the Beaufort keystream palette enrichment pattern at crib positions
is intrinsic to the carved CT97, and characterizes its spatial structure.

Family: stego/coupling
Status: active
Score: N/A (statistical characterization)

Six tests:
  T1: Mask-independence of crib keystream (verification)
  T2: PT letters that would produce palette keystream at non-crib positions
  T3: Gap analysis between enriched zones
  T4: Positional autocorrelation of palette membership
  T5: Consecutive palette runs significance
  T6: Periodic structure explaining palette positions
"""

import sys, os, json, random, datetime
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS,
    NULL_PALETTE, CONSENSUS_NULL_POSITIONS,
    BEAUFORT_KEYSTREAM_AT_CRIBS, BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    ALPH, ALPH_IDX, MOD
)

random.seed(42)
MC_TRIALS = 100_000

PALETTE = set(NULL_PALETTE)
PALETTE_INDICES = frozenset(ALPH_IDX[c] for c in PALETTE)

# Crib positions in order
ENE_POS = list(range(21, 34))  # 13 positions
BCL_POS = list(range(63, 74))  # 11 positions
ALL_CRIB_POS = ENE_POS + BCL_POS  # 24 positions

# Beaufort keystream at cribs: k[i] = (CT[i] + PT[i]) % 26
KS_STR = BEAUFORT_KEYSTREAM_AT_CRIBS
KS_VALS = list(BEAUFORT_KEY_ENE + BEAUFORT_KEY_BC)

# Binary palette membership: 1 if keystream value is in palette
BINARY = [1 if KS_STR[i] in PALETTE else 0 for i in range(24)]
N_PAL = sum(BINARY)  # 13

# Palette positions among the 24 crib keystream values (0-indexed within crib array)
PAL_CRIB_INDICES = [i for i in range(24) if BINARY[i]]
# Actual CT positions where keystream is palette
PAL_CT_POSITIONS = [ALL_CRIB_POS[i] for i in PAL_CRIB_INDICES]

results = {
    "experiment": "E-ENRICHMENT-TOPOLOGY",
    "timestamp": datetime.datetime.now().isoformat(),
    "conventions": {
        "positions": "0-indexed",
        "alphabet_map": "A=0 ... Z=25",
        "cipher_variant": "Beaufort K=(CT+PT)%26",
        "scope": "CT97"
    },
    "tests": {}
}


def print_header(test_id, title):
    print(f"\n{'='*70}")
    print(f"  TEST {test_id}: {title}")
    print(f"{'='*70}")


# =====================================================================
# TEST 1: Mask-independence of crib keystream
# =====================================================================
print_header("T1", "Mask-independence of crib keystream")

# The keystream at crib positions is k[i] = (CT[i] + PT[i]) % 26.
# This depends ONLY on CT and PT at those positions, not on any mask.
# Verify this is true by computing directly.

ks_direct = []
for pos in ALL_CRIB_POS:
    ct_val = ALPH_IDX[CT[pos]]
    pt_val = ALPH_IDX[CRIB_DICT[pos]]
    k_val = (ct_val + pt_val) % MOD
    ks_direct.append(k_val)

assert ks_direct == KS_VALS, "Keystream mismatch!"

# The mask plays NO role in computing crib keystream.
# Even if we change which positions are nulls, the CT characters at
# crib positions don't change (cribs are at FIXED positions in CT97).
t1_result = {
    "description": "Crib keystream k[i]=(CT[i]+PT[i])%26 is mask-independent",
    "verified": True,
    "keystream_ENE": KS_STR[:13],
    "keystream_BCL": KS_STR[13:],
    "palette_count_ENE": sum(BINARY[:13]),
    "palette_count_BCL": sum(BINARY[13:]),
    "palette_count_total": N_PAL,
    "conclusion": "Enrichment is a property of the CARVED TEXT, not of any mask model"
}
results["tests"]["T1_mask_independence"] = t1_result

print(f"Keystream ENE: {KS_STR[:13]}  palette: {sum(BINARY[:13])}/13")
print(f"Keystream BCL: {KS_STR[13:]}  palette: {sum(BINARY[13:])}/11")
print(f"Total palette: {N_PAL}/24")
print(f"VERIFIED: keystream at crib positions is mask-independent")


# =====================================================================
# TEST 2: PT letters that would produce palette keystream at non-crib positions
# =====================================================================
print_header("T2", "Palette-generating PT letters at non-crib positions")

# For each non-crib, non-null position: what PT letters would make
# the Beaufort keystream a palette letter?
# Under Beaufort: K = (CT + PT) % 26, so PT = (K - CT) % 26
# For each palette keystream value K_pal, PT = (K_pal - CT[i]) % 26

non_crib_non_null = sorted(
    set(range(CT_LEN)) - CRIB_POSITIONS - CONSENSUS_NULL_POSITIONS
)

COMMON_ENGLISH = set("ETAOINSR")  # top 8 by frequency
ENGLISH_FREQ = {  # approximate relative frequencies
    'E': 0.127, 'T': 0.091, 'A': 0.082, 'O': 0.075,
    'I': 0.070, 'N': 0.067, 'S': 0.063, 'R': 0.060,
    'H': 0.061, 'D': 0.043, 'L': 0.040, 'C': 0.028,
    'U': 0.028, 'M': 0.024, 'W': 0.024, 'F': 0.022,
    'G': 0.020, 'Y': 0.020, 'P': 0.019, 'B': 0.015,
    'V': 0.010, 'K': 0.008, 'J': 0.002, 'X': 0.002,
    'Q': 0.001, 'Z': 0.001
}

position_data = []
common_and_palette_count = 0
total_non_crib = len(non_crib_non_null)

for pos in non_crib_non_null:
    ct_val = ALPH_IDX[CT[pos]]
    # What PT letters produce palette keystream?
    palette_pts = []
    for pal_ch in sorted(PALETTE):
        k_val = ALPH_IDX[pal_ch]
        pt_val = (k_val - ct_val) % MOD
        pt_ch = ALPH[pt_val]
        palette_pts.append((pal_ch, pt_ch))

    # Are any of these PT letters common English letters?
    common_pts = [(k, p) for k, p in palette_pts if p in COMMON_ENGLISH]
    if common_pts:
        common_and_palette_count += 1

    # Expected probability that at least one of 7 random PT values is in top-8
    # P(at least 1 of 7 in top-8) = 1 - (18/26)^7 = 1 - 0.1258 = 0.874
    # So almost all positions will have at least one common English letter mapping

    # Better metric: sum of English frequencies for PT letters that map to palette
    freq_sum = sum(ENGLISH_FREQ.get(p, 0) for _, p in palette_pts)

    position_data.append({
        "pos": pos,
        "ct": CT[pos],
        "palette_pt_pairs": palette_pts,
        "common_english_pts": common_pts,
        "freq_sum": freq_sum
    })

avg_freq_sum = sum(d["freq_sum"] for d in position_data) / len(position_data)

# Under random, each palette letter maps to a random PT letter.
# Expected freq_sum for 7 random letters = 7 * (1/26) * sum(all freqs) = 7/26 = 0.269
expected_freq_sum = 7.0 / 26.0

t2_result = {
    "description": "For non-crib non-null positions, what PT makes keystream palette?",
    "n_positions": total_non_crib,
    "positions_with_common_english_palette_pt": common_and_palette_count,
    "fraction": common_and_palette_count / total_non_crib,
    "expected_fraction": "~0.874 (1-(18/26)^7)",
    "avg_english_freq_sum": round(avg_freq_sum, 4),
    "expected_freq_sum": round(expected_freq_sum, 4),
    "conclusion": "Most positions trivially have common-English PT that maps to palette; "
                  "this metric is uninformative as a mask discriminator"
}
results["tests"]["T2_palette_generating_pt"] = t2_result

print(f"Non-crib, non-null positions: {total_non_crib}")
print(f"Positions with common-English PT mapping to palette: {common_and_palette_count}/{total_non_crib} ({common_and_palette_count/total_non_crib:.1%})")
print(f"Expected under random: ~87.4%")
print(f"Avg English freq sum for palette-PT letters: {avg_freq_sum:.4f} (expected: {expected_freq_sum:.4f})")
print(f"Conclusion: metric is near-trivial (7/26 coverage makes most positions qualify)")

# More informative: for the top-frequency-sum positions, what are they?
position_data.sort(key=lambda d: d["freq_sum"], reverse=True)
print(f"\nTop 10 positions by English freq sum of palette-generating PT:")
for d in position_data[:10]:
    pts = [(k, p) for k, p in d["palette_pt_pairs"] if p in COMMON_ENGLISH]
    print(f"  pos {d['pos']:2d} CT={d['ct']} freq_sum={d['freq_sum']:.3f}  common: {pts}")


# =====================================================================
# TEST 3: Gap analysis between enriched zones
# =====================================================================
print_header("T3", "Gap analysis between enriched zones")

# ENE enriched zone: positions 27-32 (4 palette in 6 keystream values)
# BCL enriched zone: positions 63-70 (7 palette in 8 keystream values)
# Gap: positions 33-62

gap_positions = list(range(33, 63))
gap_nulls = sorted(set(gap_positions) & CONSENSUS_NULL_POSITIONS)
gap_cribs = sorted(set(gap_positions) & CRIB_POSITIONS)
gap_non_null_non_crib = sorted(set(gap_positions) - CONSENSUS_NULL_POSITIONS - CRIB_POSITIONS)

print(f"Gap region: positions 33-62 ({len(gap_positions)} positions)")
print(f"Nulls in gap: {gap_nulls} (count: {len(gap_nulls)})")
print(f"Crib positions in gap: {gap_cribs} (count: {len(gap_cribs)})")
print(f"Non-null, non-crib in gap: {len(gap_non_null_non_crib)} positions")
print(f"Gap null positions and their values:")
for p in gap_nulls:
    print(f"  pos {p}: CT[{p}] = {CT[p]}")

# Test periods that would produce enrichment at both 27-32 and 63-70
print(f"\nPeriod analysis: which periods P align both enriched zones?")
print(f"Enriched zone 1: positions 27-32 (ENE)")
print(f"Enriched zone 2: positions 63-70 (BCL)")

# For each period P, compute residue classes of enriched positions
# and see if they overlap significantly
period_results = []
for P in range(2, 49):
    ene_residues = set(p % P for p in range(27, 33))
    bcl_residues = set(p % P for p in range(63, 71))
    overlap = ene_residues & bcl_residues
    union = ene_residues | bcl_residues
    # How many distinct residue classes cover both zones?
    all_residues = set(p % P for p in list(range(27, 33)) + list(range(63, 71)))
    # Jaccard similarity
    jaccard = len(overlap) / len(union) if union else 0
    period_results.append({
        "period": P,
        "ene_residues": sorted(ene_residues),
        "bcl_residues": sorted(bcl_residues),
        "overlap": sorted(overlap),
        "n_overlap": len(overlap),
        "n_union": len(union),
        "jaccard": round(jaccard, 3),
        "n_distinct_classes": len(all_residues)
    })

# Sort by fewest distinct classes (most compact covering)
period_results.sort(key=lambda d: (d["n_distinct_classes"], -d["jaccard"]))

print(f"\nTop 10 periods by compactness (fewest residue classes to cover both zones):")
for pr in period_results[:10]:
    print(f"  P={pr['period']:2d}: {pr['n_distinct_classes']} classes, "
          f"overlap={pr['n_overlap']}, Jaccard={pr['jaccard']:.3f}, "
          f"classes={sorted(set(p % pr['period'] for p in list(range(27,33)) + list(range(63,71))))}")

# Special attention to periods that make both zones fall in SAME residue classes
print(f"\nPeriods where overlap = ENE residues (BCL contains all ENE residues):")
for pr in period_results:
    ene_res = set(pr["ene_residues"])
    if ene_res <= set(pr["bcl_residues"]):
        print(f"  P={pr['period']:2d}: ENE residues {pr['ene_residues']} "
              f"subset of BCL {pr['bcl_residues']}")

t3_result = {
    "description": "Gap analysis between ENE(27-32) and BCL(63-70) enriched zones",
    "gap_range": "33-62",
    "gap_null_positions": gap_nulls,
    "gap_null_count": len(gap_nulls),
    "gap_null_values": {str(p): CT[p] for p in gap_nulls},
    "top_periods": period_results[:10],
    "conclusion": "See output for period alignment analysis"
}
results["tests"]["T3_gap_analysis"] = t3_result


# =====================================================================
# TEST 4: Positional autocorrelation of palette membership
# =====================================================================
print_header("T4", "Autocorrelation of palette membership binary sequence")

# Binary sequence: [0,0,0,1,0,0,1,1,0,1,1,1,0, 1,0,1,1,1,1,1,1,0,0,0]
assert BINARY == [0,0,0,1,0,0,1,1,0,1,1,1,0, 1,0,1,1,1,1,1,1,0,0,0], f"Binary mismatch: {BINARY}"
n = len(BINARY)
mean_b = N_PAL / n

def autocorrelation(seq, lag):
    """Compute autocorrelation at given lag for binary sequence."""
    n = len(seq)
    if lag >= n:
        return 0.0
    mean = sum(seq) / n
    num = sum((seq[i] - mean) * (seq[i + lag] - mean) for i in range(n - lag))
    denom = sum((seq[i] - mean) ** 2 for i in range(n))
    if denom == 0:
        return 0.0
    return num / denom

print(f"Binary sequence: {BINARY}")
print(f"N={n}, palette count={N_PAL}, mean={mean_b:.3f}")
print()

observed_ac = {}
for lag in range(1, 13):
    ac = autocorrelation(BINARY, lag)
    observed_ac[lag] = ac
    print(f"  Lag {lag:2d}: autocorrelation = {ac:+.4f}")

# Monte Carlo: for 100K random binary sequences with exactly 13 ones in 24 positions
print(f"\nMonte Carlo ({MC_TRIALS:,} trials): distribution of autocorrelation at each lag")
print(f"  (random sequences with exactly {N_PAL} ones in {n} positions)")

mc_ac = {lag: [] for lag in range(1, 13)}
base_seq = [1] * N_PAL + [0] * (n - N_PAL)

for trial in range(MC_TRIALS):
    random.shuffle(base_seq)
    for lag in range(1, 13):
        mc_ac[lag].append(autocorrelation(base_seq, lag))

print(f"\n  {'Lag':>3s}  {'Observed':>9s}  {'MC mean':>9s}  {'MC std':>9s}  {'p-value':>9s}  {'Verdict':>12s}")
ac_pvalues = {}
for lag in range(1, 13):
    obs = observed_ac[lag]
    mc_vals = mc_ac[lag]
    mc_mean = sum(mc_vals) / len(mc_vals)
    mc_std = (sum((v - mc_mean) ** 2 for v in mc_vals) / len(mc_vals)) ** 0.5
    # Two-sided p-value
    p_val = sum(1 for v in mc_vals if abs(v) >= abs(obs)) / MC_TRIALS
    ac_pvalues[lag] = p_val
    verdict = "SIGNIFICANT" if p_val < 0.05/12 else ("marginal" if p_val < 0.05 else "not sig")
    print(f"  {lag:3d}  {obs:+9.4f}  {mc_mean:+9.4f}  {mc_std:9.4f}  {p_val:9.4f}  {verdict:>12s}")

# Bonferroni correction for 12 lags
bonf_threshold = 0.05 / 12
significant_lags = [lag for lag in range(1, 13) if ac_pvalues[lag] < bonf_threshold]
print(f"\nBonferroni threshold (k=12): p < {bonf_threshold:.4f}")
print(f"Significant lags: {significant_lags if significant_lags else 'NONE'}")

t4_result = {
    "description": "Autocorrelation of palette membership binary sequence at lags 1-12",
    "binary_sequence": BINARY,
    "observed_autocorrelation": {str(k): round(v, 4) for k, v in observed_ac.items()},
    "mc_trials": MC_TRIALS,
    "p_values": {str(k): round(v, 4) for k, v in ac_pvalues.items()},
    "bonferroni_threshold": round(bonf_threshold, 4),
    "significant_lags_bonferroni": significant_lags
}
results["tests"]["T4_autocorrelation"] = t4_result


# =====================================================================
# TEST 5: Consecutive palette runs
# =====================================================================
print_header("T5", "Consecutive palette runs significance")

def longest_run(seq, target=1):
    """Find longest consecutive run of target value."""
    max_run = 0
    current = 0
    for v in seq:
        if v == target:
            current += 1
            max_run = max(max_run, current)
        else:
            current = 0
    return max_run

def all_runs(seq, target=1):
    """Find all runs of target value, return list of (start, length)."""
    runs = []
    current_start = None
    current_len = 0
    for i, v in enumerate(seq):
        if v == target:
            if current_start is None:
                current_start = i
            current_len += 1
        else:
            if current_start is not None:
                runs.append((current_start, current_len))
            current_start = None
            current_len = 0
    if current_start is not None:
        runs.append((current_start, current_len))
    return runs

obs_longest = longest_run(BINARY)
obs_runs = all_runs(BINARY)

print(f"Binary sequence: {BINARY}")
print(f"Observed palette runs: {obs_runs}")
print(f"Longest consecutive palette run: {obs_longest}")

# Map back to CT positions
print(f"\nRuns mapped to CT positions:")
for start_idx, length in obs_runs:
    ct_positions = ALL_CRIB_POS[start_idx:start_idx + length]
    ks_letters = KS_STR[start_idx:start_idx + length]
    print(f"  Crib indices {start_idx}-{start_idx+length-1} -> "
          f"CT pos {ct_positions} -> keystream {ks_letters}")

# Monte Carlo: with 13/24 palette overall, P(longest consecutive run >= obs)?
mc_longest_runs = []
base_seq = [1] * N_PAL + [0] * (n - N_PAL)
for trial in range(MC_TRIALS):
    random.shuffle(base_seq)
    mc_longest_runs.append(longest_run(base_seq))

p_longest = sum(1 for v in mc_longest_runs if v >= obs_longest) / MC_TRIALS
mc_mean_longest = sum(mc_longest_runs) / len(mc_longest_runs)

# Distribution of longest runs
run_dist = Counter(mc_longest_runs)
print(f"\nMC distribution of longest consecutive palette run ({MC_TRIALS:,} trials, {N_PAL}/{n}):")
for length in sorted(run_dist.keys()):
    pct = run_dist[length] / MC_TRIALS * 100
    print(f"  longest={length}: {pct:.2f}%")

print(f"\nObserved longest run: {obs_longest}")
print(f"MC mean longest run: {mc_mean_longest:.2f}")
print(f"P(longest >= {obs_longest}): {p_longest:.4f}")
verdict = "SIGNIFICANT" if p_longest < 0.05 else "NOT SIGNIFICANT"
print(f"Verdict: {verdict}")

# Also test: longest run in BCL only (crib indices 13-23)
bcl_binary = BINARY[13:]
bcl_longest = longest_run(bcl_binary)
print(f"\nBCL-only binary: {bcl_binary}")
print(f"BCL longest consecutive palette run: {bcl_longest}")

# MC for BCL alone: 7/11 palette
mc_bcl_longest = []
bcl_base = [1] * 7 + [0] * 4
for trial in range(MC_TRIALS):
    random.shuffle(bcl_base)
    mc_bcl_longest.append(longest_run(bcl_base))

p_bcl = sum(1 for v in mc_bcl_longest if v >= bcl_longest) / MC_TRIALS
print(f"MC P(BCL longest >= {bcl_longest} | 7/11 palette): {p_bcl:.4f}")

t5_result = {
    "description": "Significance of consecutive palette runs in keystream",
    "observed_runs": [(s, l) for s, l in obs_runs],
    "longest_run": obs_longest,
    "mc_trials": MC_TRIALS,
    "mc_mean_longest": round(mc_mean_longest, 2),
    "p_longest_run": round(p_longest, 4),
    "bcl_longest_run": bcl_longest,
    "p_bcl_longest": round(p_bcl, 4),
    "verdict": verdict
}
results["tests"]["T5_consecutive_runs"] = t5_result


# =====================================================================
# TEST 6: Periodic structure explaining palette positions
# =====================================================================
print_header("T6", "Periodic structure of palette keystream positions")

# The 13 palette positions among 24 crib positions are at these CT positions:
print(f"Palette keystream at CT positions: {PAL_CT_POSITIONS}")
print(f"Crib-array indices: {PAL_CRIB_INDICES}")

# For each period P (2-48), find the minimum number of residue classes mod P
# needed to cover all 13 palette CT positions
print(f"\nFor each period P: minimum residue classes to cover all {len(PAL_CT_POSITIONS)} palette positions")
print(f"{'P':>3s}  {'#classes':>8s}  {'coverage':>8s}  {'classes':>40s}")

period_class_results = []
for P in range(2, 49):
    residues = set(p % P for p in PAL_CT_POSITIONS)
    n_classes = len(residues)
    # What fraction of P's residue classes are used?
    coverage = n_classes / P
    period_class_results.append({
        "period": P,
        "n_classes": n_classes,
        "total_classes": P,
        "coverage": round(coverage, 3),
        "classes": sorted(residues)
    })

# Sort by coverage (lower = more concentrated)
period_class_results.sort(key=lambda d: d["coverage"])

for pr in period_class_results[:15]:
    print(f"  {pr['period']:3d}  {pr['n_classes']:8d}  {pr['coverage']:8.3f}  {pr['classes']}")

# Monte Carlo: for each top period, how often do 13 random positions from 24
# fall into <= observed number of classes?
print(f"\nMC validation for top 5 periods:")
top_periods = period_class_results[:5]

for pr in top_periods:
    P = pr["period"]
    obs_classes = pr["n_classes"]

    # Under null: choose 13 of the 24 crib positions at random,
    # compute residues of their CT positions mod P
    mc_count = 0
    for trial in range(MC_TRIALS):
        sample_indices = random.sample(range(24), N_PAL)
        sample_ct_pos = [ALL_CRIB_POS[i] for i in sample_indices]
        sample_residues = set(p % P for p in sample_ct_pos)
        if len(sample_residues) <= obs_classes:
            mc_count += 1

    p_val = mc_count / MC_TRIALS
    print(f"  P={P:2d}: {obs_classes} classes, MC P(<={obs_classes} classes) = {p_val:.4f}")
    pr["mc_p_value"] = round(p_val, 4)

# Alternative: test against random 13 positions from 97 (not just crib positions)
print(f"\nMC validation against random 13 from 97 positions:")
for pr in top_periods:
    P = pr["period"]
    obs_classes = pr["n_classes"]

    mc_count = 0
    for trial in range(MC_TRIALS):
        sample_pos = random.sample(range(97), N_PAL)
        sample_residues = set(p % P for p in sample_pos)
        if len(sample_residues) <= obs_classes:
            mc_count += 1

    p_val = mc_count / MC_TRIALS
    print(f"  P={P:2d}: {obs_classes} classes, MC P(<={obs_classes} classes from 97) = {p_val:.4f}")
    pr["mc_p_value_from97"] = round(p_val, 4)

results["tests"]["T6_periodic_structure"] = {
    "description": "Minimum residue classes to cover palette keystream positions",
    "palette_ct_positions": PAL_CT_POSITIONS,
    "top_periods": top_periods,
    "all_periods": period_class_results
}


# =====================================================================
# SUMMARY
# =====================================================================
print(f"\n{'='*70}")
print(f"  SUMMARY")
print(f"{'='*70}")

print(f"""
T1: Crib keystream is MASK-INDEPENDENT (verified).
    Enrichment is a property of the carved text, not any mask model.

T2: At non-crib positions, ~87% trivially have a common-English PT that
    maps to a palette keystream value. This metric is uninformative.

T3: Gap (pos 33-62) contains {len(gap_nulls)} null positions: {gap_nulls}.
    Period alignment analysis identifies compact coverings.

T4: Autocorrelation of palette binary sequence.
    Significant lags (Bonferroni k=12): {significant_lags if significant_lags else 'NONE'}.

T5: Longest consecutive palette run = {obs_longest}.
    P(longest >= {obs_longest}) = {p_longest:.4f}. {verdict}.
    BCL longest = {bcl_longest}, P = {p_bcl:.4f}.

T6: Periodic structure analysis - see detailed output above.
""")

# Save results
out_path = os.path.join(_ROOT, "results", "enrichment_topology.json")
with open(out_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"Results saved to: {out_path}")
