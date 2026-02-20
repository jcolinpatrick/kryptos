#!/usr/bin/env python3
"""E-FRAC-01: Width-9 Grid Structural Analysis.

Cheap diagnostic tests on the width-9 grid hypothesis:
1. IC per column for all 9! orderings — does any ordering produce
   significantly non-uniform column ICs?
2. Lag analysis — what lag values show autocorrelation in the
   transposed text for each ordering?
3. DFT of the lag spectrum — does width-9 explain the observed
   lag-7 autocorrelation signal?
4. Crib column distribution — how do the 24 known PT positions
   distribute across columns for each ordering?
5. Bean constraint check — which orderings preserve Bean equality
   under various substitution models?

This is a minutes-scale computation, not a heavy sweep.
"""
import itertools
import json
import math
import os
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS,
    ALPH_IDX, MOD, BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_SET = set(CRIB_DICT.keys())

WIDTH = 9
N_ROWS_FULL = CT_LEN // WIDTH      # 10
REMAINDER = CT_LEN % WIDTH          # 7
# Columns 0..6 have 11 rows, columns 7..8 have 10 rows
COL_HEIGHTS = [N_ROWS_FULL + 1 if j < REMAINDER else N_ROWS_FULL
               for j in range(WIDTH)]

print(f"Width-9 grid: {WIDTH} columns")
print(f"  Full rows: {N_ROWS_FULL}, remainder: {REMAINDER}")
print(f"  Column heights: {COL_HEIGHTS}")
print(f"  Total: {sum(COL_HEIGHTS)} = {CT_LEN}")
print()


def build_columnar_perm(order):
    """Build gather permutation for columnar encryption.

    Encryption: write PT row-by-row into grid, read columns in `order`.
    output[i] = input[perm[i]]
    """
    perm = []
    for c in range(WIDTH):
        col = order[c]
        height = COL_HEIGHTS[col]
        for row in range(height):
            perm.append(row * WIDTH + col)
    return perm


def invert_perm(perm):
    """Compute inverse permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def compute_ic(values):
    """Index of coincidence for a list of integer values (0-25)."""
    n = len(values)
    if n <= 1:
        return 0.0
    freq = Counter(values)
    total = sum(f * (f - 1) for f in freq.values())
    return total / (n * (n - 1))


def compute_lag_matches(seq, lag):
    """Count positions where seq[i] == seq[i+lag]."""
    return sum(1 for i in range(len(seq) - lag) if seq[i] == seq[i + lag])


def compute_lag_expected(n, lag):
    """Expected lag matches for random sequence of length n over 26 symbols."""
    return (n - lag) / 26.0


def compute_lag_z(matches, n, lag):
    """Z-score for lag-k match count under null hypothesis (uniform random)."""
    expected = compute_lag_expected(n, lag)
    # Variance: (n-lag) * (1/26) * (25/26)
    variance = (n - lag) * (1.0 / 26.0) * (25.0 / 26.0)
    if variance <= 0:
        return 0.0
    return (matches - expected) / math.sqrt(variance)


# ═══════════════════════════════════════════════════════════════════════════
# PART 1: Basic grid properties
# ═══════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("PART 1: Basic Width-9 Grid Properties")
print("=" * 70)

# Lay out CT on 9-wide grid (row-major, identity column order)
grid = []
for row in range(N_ROWS_FULL + 1):
    start = row * WIDTH
    end = min(start + WIDTH, CT_LEN)
    grid.append(CT[start:end])
    print(f"  Row {row:2d}: {CT[start:end]}")

# CT letter frequencies
ct_freq = Counter(CT)
print(f"\nCT letter frequencies: {dict(sorted(ct_freq.items(), key=lambda x: -x[1]))}")
print(f"CT unique letters: {len(ct_freq)}")

# IC of CT itself
ct_ic = compute_ic(CT_NUM)
print(f"CT IC: {ct_ic:.4f} (random: {1/26:.4f}, English: 0.0667)")

# Per-column IC with identity ordering (columns 0-8)
print("\nPer-column IC (identity ordering):")
for col in range(WIDTH):
    col_vals = [CT_NUM[row * WIDTH + col]
                for row in range(COL_HEIGHTS[col])]
    ic = compute_ic(col_vals)
    freq = Counter(col_vals)
    print(f"  Col {col}: IC={ic:.4f}, n={len(col_vals)}, "
          f"uniq={len(freq)}, max_freq={max(freq.values())}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 2: Lag analysis on raw CT
# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("PART 2: Lag Analysis on Raw CT")
print("=" * 70)

print("Lag-k autocorrelation (raw CT):")
lag_data = []
for lag in range(1, 30):
    matches = compute_lag_matches(CT_NUM, lag)
    expected = compute_lag_expected(CT_LEN, lag)
    z = compute_lag_z(matches, CT_LEN, lag)
    lag_data.append({"lag": lag, "matches": matches,
                     "expected": round(expected, 2), "z": round(z, 2)})
    flag = " ***" if abs(z) > 2.0 else ""
    print(f"  lag={lag:2d}: {matches:2d} matches "
          f"(expected {expected:.1f}, z={z:+.2f}){flag}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 3: Per-column IC for all 9! orderings
# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("PART 3: Per-Column IC Analysis (all 362,880 orderings)")
print("=" * 70)

t0 = time.time()

# For each ordering, compute: mean column IC, IC variance, max column IC
ordering_metrics = []

for order in itertools.permutations(range(WIDTH)):
    perm = build_columnar_perm(order)
    inv_perm = invert_perm(perm)

    # After undoing transposition: intermediate[j] = CT[inv_perm[j]]
    # Column c of PT grid = positions c, c+9, c+18, ...
    # After undoing trans, the values in column c come from
    # CT positions inv_perm[c], inv_perm[c+9], ...
    col_ics = []
    for col in range(WIDTH):
        col_vals = [CT_NUM[inv_perm[row * WIDTH + col]]
                    for row in range(COL_HEIGHTS[col])]
        col_ics.append(compute_ic(col_vals))

    ic_mean = sum(col_ics) / WIDTH
    ic_var = sum((ic - ic_mean) ** 2 for ic in col_ics) / WIDTH
    ic_max = max(col_ics)

    # Also compute IC of the full un-transposed text
    untrans = [CT_NUM[inv_perm[j]] for j in range(CT_LEN)]
    full_ic = compute_ic(untrans)

    # Lag-9 matches in un-transposed text (should be meaningful for width-9)
    lag9_matches = compute_lag_matches(untrans, 9)
    lag7_matches = compute_lag_matches(untrans, 7)

    ordering_metrics.append({
        "order": list(order),
        "ic_mean": ic_mean,
        "ic_var": ic_var,
        "ic_max": ic_max,
        "full_ic": full_ic,
        "lag9": lag9_matches,
        "lag7": lag7_matches,
    })

elapsed_p3 = time.time() - t0
print(f"Computed in {elapsed_p3:.1f}s")

# Analyze distributions
ic_means = [m["ic_mean"] for m in ordering_metrics]
ic_vars = [m["ic_var"] for m in ordering_metrics]
ic_maxes = [m["ic_max"] for m in ordering_metrics]
full_ics = [m["full_ic"] for m in ordering_metrics]
lag9s = [m["lag9"] for m in ordering_metrics]
lag7s = [m["lag7"] for m in ordering_metrics]

for name, vals in [("mean_col_IC", ic_means), ("col_IC_var", ic_vars),
                   ("max_col_IC", ic_maxes), ("full_IC", full_ics),
                   ("lag9", lag9s), ("lag7", lag7s)]:
    avg = sum(vals) / len(vals)
    std = (sum((v - avg) ** 2 for v in vals) / len(vals)) ** 0.5
    mx = max(vals)
    mn = min(vals)
    print(f"\n{name}:")
    print(f"  mean={avg:.4f}, std={std:.4f}, min={mn:.4f}, max={mx:.4f}")

    # Top 5 orderings
    sorted_indices = sorted(range(len(vals)), key=lambda i: vals[i], reverse=True)
    print(f"  Top 5:")
    for rank, idx in enumerate(sorted_indices[:5]):
        m = ordering_metrics[idx]
        print(f"    #{rank+1}: {name}={vals[idx]:.4f}, order={m['order']}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 4: Crib distribution across columns
# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("PART 4: Crib Distribution Across Width-9 Columns")
print("=" * 70)

# With identity ordering, which columns do crib positions fall in?
print("Identity ordering (no transposition):")
for pos in sorted(CRIB_SET):
    col = pos % WIDTH
    row = pos // WIDTH
    print(f"  PT pos {pos:2d} ({CRIB_DICT[pos]}) → row={row}, col={col}")

crib_cols = Counter(pos % WIDTH for pos in CRIB_SET)
print(f"\nCribs per column: {dict(sorted(crib_cols.items()))}")

# ENE crib (pos 21-33): columns
ene_cols = [(pos, pos % WIDTH) for pos in range(21, 34)]
bc_cols = [(pos, pos % WIDTH) for pos in range(63, 74)]
print(f"\nENE positions → columns: {ene_cols}")
print(f"BC positions → columns:  {bc_cols}")

# For each ordering, how many crib positions map to the same column
# after transposition reversal?
print("\nCrib column concentration (top orderings):")
best_concentration = []
for m in ordering_metrics:
    order = m["order"]
    perm = build_columnar_perm(order)
    inv_perm = invert_perm(perm)

    # After undoing transposition, crib position p maps to CT[inv_perm[p]]
    # The column of p in the PT grid is p % WIDTH
    # We want to know: does the transposition move crib positions
    # such that they cluster in certain columns of the CT?

    # Actually, what matters for substitution analysis:
    # After trans reversal, intermediate[j] = CT[inv_perm[j]]
    # Crib constraints: intermediate[crib_pos] = sub(PT[crib_pos])
    # So intermediate at crib positions tells us about the substitution

    # The *crib coverage per column of the intermediate grid* is still
    # determined by crib_pos % WIDTH (since crib_pos is in PT space)
    # This is invariant of the transposition ordering!

    # BUT: what IS ordering-dependent is which CT positions
    # contribute to the crib constraints. Let's track that.
    ct_positions_for_cribs = [inv_perm[p] for p in sorted(CRIB_SET)]
    ct_col_dist = Counter(p % WIDTH for p in ct_positions_for_cribs)
    max_ct_col_count = max(ct_col_dist.values()) if ct_col_dist else 0
    best_concentration.append((max_ct_col_count, order, ct_col_dist))

best_concentration.sort(reverse=True)
print("Top orderings by max crib CT-column concentration:")
for count, order, dist in best_concentration[:5]:
    print(f"  max={count}, order={list(order)}, dist={dict(sorted(dist.items()))}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 5: Does width-9 explain the lag-7 signal?
# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("PART 5: Width-9 ↔ Lag-7 Relationship")
print("=" * 70)

# The raw CT has lag-7 z≈3.036. Can any width-9 columnar transposition
# convert a text with NO lag-7 signal into one WITH lag-7?

# For each ordering, compute the lag-7 matches in the transposed text
# (i.e., in CT space). If width-9 transposition naturally creates lag-7
# correlations, most orderings should show elevated lag-7.

lag7_raw = compute_lag_matches(CT_NUM, 7)
lag7_z_raw = compute_lag_z(lag7_raw, CT_LEN, 7)
print(f"Raw CT lag-7: {lag7_raw} matches, z={lag7_z_raw:.2f}")

# Distribution of lag-7 in un-transposed text across orderings
print(f"\nLag-7 in un-transposed text (CT after reversing each ordering):")
print(f"  Mean: {sum(lag7s)/len(lag7s):.2f}")
print(f"  Max:  {max(lag7s)}")
print(f"  Min:  {min(lag7s)}")

lag7_dist = Counter(lag7s)
print(f"  Distribution:")
for val in sorted(lag7_dist.keys(), reverse=True):
    print(f"    lag7={val}: {lag7_dist[val]} orderings")

# Key question: if we undo width-9 transposition, does lag-7 go AWAY?
# If yes, width-9 transposition could be CREATING the lag-7 artifact.
lag7_below_raw = sum(1 for v in lag7s if v < lag7_raw)
lag7_above_raw = sum(1 for v in lag7s if v > lag7_raw)
print(f"\n  Orderings where un-trans lag-7 < raw ({lag7_raw}): "
      f"{lag7_below_raw} ({100*lag7_below_raw/len(lag7s):.1f}%)")
print(f"  Orderings where un-trans lag-7 > raw ({lag7_raw}): "
      f"{lag7_above_raw} ({100*lag7_above_raw/len(lag7s):.1f}%)")

# Also check: for orderings that REDUCE lag-7, do they INCREASE lag-9?
print("\nCorrelation between lag-7 and lag-9 in un-transposed text:")
# Simple: count orderings where lag-7 decreases AND lag-9 increases
lag9_raw = compute_lag_matches(CT_NUM, 9)
both_changed = sum(1 for i in range(len(lag7s))
                   if lag7s[i] < lag7_raw and lag9s[i] > lag9_raw)
print(f"  Raw lag-9: {lag9_raw}")
print(f"  Orderings where lag-7↓ AND lag-9↑: {both_changed}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 6: Key value analysis for top orderings
# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("PART 6: Key Value Analysis (Vigenère model, top orderings)")
print("=" * 70)

# For the top orderings (by various metrics), compute the implied
# Vigenère key values at crib positions and look for structure.

def get_key_values(perm, variant=0):
    """Derive key values at crib positions after undoing transposition.

    Model B (trans→sub): CT[i] = sub(PT[perm[i]], key[i])
    So: key[i] = (CT[i] - PT[perm[i]]) mod 26 for Vigenère
    """
    keys = {}
    for i, src in enumerate(perm):
        if src in CRIB_SET:
            pt_val = CRIB_PT_NUM[src]
            ct_val = CT_NUM[i]
            if variant == 0:    # Vigenère
                k = (ct_val - pt_val) % MOD
            elif variant == 1:  # Beaufort
                k = (ct_val + pt_val) % MOD
            else:               # Variant Beaufort
                k = (pt_val - ct_val) % MOD
            keys[i] = k
    return keys


def analyze_key_structure(keys):
    """Look for patterns in derived key values."""
    positions = sorted(keys.keys())
    values = [keys[p] for p in positions]

    # Check for runs (consecutive equal values)
    runs = 0
    max_run = 1
    current_run = 1
    for i in range(1, len(values)):
        if values[i] == values[i-1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            if current_run > 1:
                runs += 1
            current_run = 1
    if current_run > 1:
        runs += 1

    # Check for arithmetic progressions
    diffs = [(values[i+1] - values[i]) % MOD for i in range(len(values)-1)]
    diff_freq = Counter(diffs)

    # Unique values
    unique = len(set(values))

    return {
        "n_constrained": len(values),
        "unique_keys": unique,
        "max_run": max_run,
        "n_runs": runs,
        "most_common_diff": diff_freq.most_common(1)[0] if diff_freq else (None, 0),
        "key_values": values,
        "positions": positions,
    }


# Sort by IC variance (highest first) - likely to show column-dependent sub
sorted_by_ic_var = sorted(range(len(ordering_metrics)),
                          key=lambda i: ordering_metrics[i]["ic_var"],
                          reverse=True)

print("Top 10 orderings by IC variance — key analysis (Vigenère):")
for rank, idx in enumerate(sorted_by_ic_var[:10]):
    m = ordering_metrics[idx]
    order = m["order"]
    perm = build_columnar_perm(order)

    for variant, vname in [(0, "Vig"), (1, "Beau"), (2, "VB")]:
        keys = get_key_values(perm, variant)
        analysis = analyze_key_structure(keys)

        if rank < 3:  # Show detail for top 3
            print(f"\n  #{rank+1} order={order} ({vname}):")
            print(f"    Constrained: {analysis['n_constrained']}")
            print(f"    Unique keys: {analysis['unique_keys']}/26")
            print(f"    Max run: {analysis['max_run']}")
            print(f"    Key values: {analysis['key_values']}")
            print(f"    Positions:  {analysis['positions']}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 7: Bean constraint analysis under width-9
# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("PART 7: Bean Constraint Analysis Under Width-9")
print("=" * 70)

# Bean equality: key[27] == key[65]
# Bean inequalities: key[a] != key[b] for 21 pairs
# Under transposition, these constraints move:
# In Model B, key[i] at CT position i.
# After transposition σ, PT position p maps to CT position σ⁻¹(p).
# So Bean equality becomes: key at CT positions inv_perm[27] and inv_perm[65]

bean_pass_count = 0
bean_orderings = []

for order in itertools.permutations(range(WIDTH)):
    perm = build_columnar_perm(order)
    inv_perm = invert_perm(perm)

    # Get key values at all crib positions (Vigenère)
    keys = get_key_values(perm, variant=0)

    # Check if positions 27 and 65 are both constrained
    ct_27 = inv_perm[27]  # CT position corresponding to PT position 27
    ct_65 = inv_perm[65]
    # We need key[ct_27] and key[ct_65]
    # But key[i] is only known where perm[i] is a crib position
    # For Model B: key[ct_pos] = (CT[ct_pos] - PT[perm[ct_pos]]) mod 26
    # perm[ct_27] = perm[inv_perm[27]] = 27 (which IS a crib position)
    # perm[ct_65] = perm[inv_perm[65]] = 65 (which IS a crib position)
    # So both are always constrained!

    k27 = (CT_NUM[ct_27] - CRIB_PT_NUM[27]) % MOD
    k65 = (CT_NUM[ct_65] - CRIB_PT_NUM[65]) % MOD

    bean_eq = (k27 == k65)

    # Check inequalities
    bean_ineq_pass = True
    for a, b in BEAN_INEQ:
        if a in CRIB_SET and b in CRIB_SET:
            ct_a = inv_perm[a]
            ct_b = inv_perm[b]
            ka = (CT_NUM[ct_a] - CRIB_PT_NUM[a]) % MOD
            kb = (CT_NUM[ct_b] - CRIB_PT_NUM[b]) % MOD
            if ka == kb:
                bean_ineq_pass = False
                break

    if bean_eq and bean_ineq_pass:
        bean_pass_count += 1
        bean_orderings.append(list(order))

print(f"Orderings passing Bean equality (k[27]==k[65]): checking...")
# Count just equality first
eq_count = 0
for order in itertools.permutations(range(WIDTH)):
    perm = build_columnar_perm(order)
    inv_perm = invert_perm(perm)
    ct_27 = inv_perm[27]
    ct_65 = inv_perm[65]
    k27 = (CT_NUM[ct_27] - CRIB_PT_NUM[27]) % MOD
    k65 = (CT_NUM[ct_65] - CRIB_PT_NUM[65]) % MOD
    if k27 == k65:
        eq_count += 1

print(f"Bean equality passes: {eq_count} / 362,880 ({100*eq_count/362880:.2f}%)")
print(f"Bean full passes (eq + ineq, Vig): {bean_pass_count} / 362,880 "
      f"({100*bean_pass_count/362880:.2f}%)")
print(f"Expected random (equality alone): ~{362880//26} ({100/26:.2f}%)")

if bean_orderings:
    print(f"\nFirst 20 Bean-passing orderings:")
    for order in bean_orderings[:20]:
        perm = build_columnar_perm(order)
        keys = get_key_values(perm, variant=0)
        print(f"  order={order}, key vals at cribs: {sorted(keys.items())[:8]}...")

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
elapsed_total = time.time() - t0 + elapsed_p3

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Total time: {elapsed_total:.1f}s")
print()
print("Key findings:")
print(f"  1. CT IC = {ct_ic:.4f} (below random {1/26:.4f})")
print(f"  2. Lag-7 raw: {lag7_raw} matches (z={lag7_z_raw:.2f})")
print(f"  3. Width-9 orderings that reduce lag-7: "
      f"{lag7_below_raw}/{len(lag7s)}")
print(f"  4. Bean-passing orderings (Vig): {bean_pass_count}")
print(f"  5. Max column IC variance: {max(ic_vars):.6f}")
print()

# Save artifacts
os.makedirs("results/frac", exist_ok=True)
artifact = {
    "experiment": "E-FRAC-01",
    "description": "Width-9 grid structural analysis",
    "width": WIDTH,
    "col_heights": COL_HEIGHTS,
    "ct_ic": ct_ic,
    "lag_analysis": lag_data,
    "lag7_raw": lag7_raw,
    "lag7_z_raw": round(lag7_z_raw, 3),
    "lag9_raw": lag9_raw,
    "bean_eq_passes": eq_count,
    "bean_full_passes": bean_pass_count,
    "bean_orderings_sample": bean_orderings[:50],
    "top_orderings_by_ic_var": [
        {"order": ordering_metrics[i]["order"],
         "ic_var": round(ordering_metrics[i]["ic_var"], 6),
         "ic_mean": round(ordering_metrics[i]["ic_mean"], 4),
         "ic_max": round(ordering_metrics[i]["ic_max"], 4)}
        for i in sorted_by_ic_var[:50]
    ],
    "lag7_distribution_untrans": dict(lag7_dist),
    "elapsed_seconds": round(elapsed_total, 1),
}
path = "results/frac/e_frac_01_w9_structural.json"
with open(path, "w") as f:
    json.dump(artifact, f, indent=2)
print(f"Saved to {path}")
print()
print(f"RESULT: structural_analysis width=9 bean_passes={bean_pass_count} "
      f"lag7_reducible={lag7_below_raw}/{len(lag7s)}")
