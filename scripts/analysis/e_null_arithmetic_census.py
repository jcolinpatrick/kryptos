#!/usr/bin/env python3
"""
Cipher: stego_analysis
Family: analysis
Status: active
Keyspace: analytical (17 null positions x 48 lags x 26 deltas)
Last run:
Best score:
"""
"""
E-NULL-ARITHMETIC-CENSUS: Phase 1 of Stego Layer Solve Plan

For each of the 17 consensus null positions, determine whether its value
is FORCED by local constant-difference constraints from non-null neighbors.

The Stehle Delta4=5 anomaly at positions 55-63 shows that null values at
positions 58,59 are uniquely determined by the Δ4=5 rule from surrounding
non-null characters. This script systematically checks ALL null positions
for similar arithmetic constraints.

Tests:
  T1.1 — Exhaustive local constraint census (all lags, all null positions)
  T1.2 — Palette compatibility check (are forced values always palette?)
  T1.3 — Uniqueness check (how many palette letters satisfy all constraints?)
  T1.4 — Monte Carlo baseline (expected constraints under random null values)

Output: results/null_arithmetic_constraint_census.json
Repro: PYTHONPATH=src python3 -u scripts/analysis/e_null_arithmetic_census.py
"""

import json
import sys
import os
import time
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, CRIB_DICT
)

# ── Setup ──
CT_NUM = [ALPH_IDX[c] for c in CT]
NULL_POS = sorted(CONSENSUS_NULL_POSITIONS)
NON_NULL_POS = sorted(set(range(CT_LEN)) - CONSENSUS_NULL_POSITIONS)
PALETTE_VALS = frozenset(ALPH_IDX[c] for c in NULL_PALETTE)
PALETTE_LETTERS = sorted(NULL_PALETTE)

print("=" * 70)
print("E-NULL-ARITHMETIC-CENSUS: Phase 1 — Local Constraint Census")
print("=" * 70)
print(f"CT: {CT}")
print(f"Null positions ({len(NULL_POS)}): {NULL_POS}")
print(f"Palette: {PALETTE_LETTERS} = values {sorted(PALETTE_VALS)}")
print()


# ══════════════════════════════════════════════════════════════════════════
# T1.1: EXHAUSTIVE LOCAL CONSTRAINT CENSUS
# ══════════════════════════════════════════════════════════════════════════
# For each null position p, find all (lag d, delta v) pairs where:
#   - There exist non-null positions that form a constant-difference chain
#     through p at lag d with delta v
#   - Specifically: for some non-null q, CT[q] is known, and the chain
#     q → p at lag d with delta v forces CT[p] = (CT[q] + v) mod 26
#     or CT[p] = (CT[q] - v) mod 26
#
# More precisely: for lag d, if position (p-d) is non-null, then the
# delta from (p-d) to p is CT[p] - CT[p-d] mod 26. If position (p+d)
# is also non-null, then delta from p to (p+d) is CT[p+d] - CT[p] mod 26.
# If both deltas equal the same v, then p is "constrained" by the chain.

print("T1.1: Exhaustive local constraint census")
print("-" * 50)

constraint_report = {}

for p in NULL_POS:
    p_val = CT_NUM[p]
    p_letter = CT[p]
    constraints = []

    for d in range(1, 49):  # lags 1..48
        # Check if both (p-d) and (p+d) exist and are non-null
        left = p - d
        right = p + d

        has_left = (0 <= left < CT_LEN) and (left not in CONSENSUS_NULL_POSITIONS)
        has_right = (0 <= right < CT_LEN) and (right not in CONSENSUS_NULL_POSITIONS)

        if has_left and has_right:
            # Both neighbors exist: check if they define a consistent delta through p
            left_val = CT_NUM[left]
            right_val = CT_NUM[right]

            # For p to be on a constant-difference chain at lag d:
            # CT[left] + delta = CT[p], CT[p] + delta = CT[right]
            # So delta = CT[p] - CT[left] = CT[right] - CT[p] (mod 26)
            # This means CT[right] - CT[left] = 2*delta (mod 26)
            # And CT[p] = (CT[left] + CT[right]) / 2 (mod 26) — midpoint

            delta_left = (p_val - left_val) % MOD
            delta_right = (right_val - p_val) % MOD

            if delta_left == delta_right:
                delta = delta_left
                # p is forced: CT[p] = (CT[left] + delta) % 26
                forced_val = (left_val + delta) % MOD
                assert forced_val == p_val, f"Consistency check failed at pos {p}"

                # How many palette letters would satisfy this constraint?
                palette_compatible = [v for v in PALETTE_VALS if v == forced_val]

                constraints.append({
                    "lag": d,
                    "delta": delta,
                    "left_pos": left,
                    "left_letter": CT[left],
                    "right_pos": right,
                    "right_letter": CT[right],
                    "forced_val": forced_val,
                    "forced_letter": chr(forced_val + ord('A')),
                    "is_palette": forced_val in PALETTE_VALS,
                    "left_is_crib": left in CRIB_POSITIONS,
                    "right_is_crib": right in CRIB_POSITIONS,
                })

        elif has_left and not has_right:
            # Only left neighbor: p's value defines the delta, but it's not
            # constrained (one-sided). Skip — not a forcing constraint.
            pass
        elif has_right and not has_left:
            # Only right neighbor: same — not forced.
            pass

    # Also check chain constraints where p is constrained by TWO chains
    # at the SAME lag but different anchors (overconstrained)
    lag_groups = defaultdict(list)
    for c in constraints:
        lag_groups[c["lag"]].append(c)

    constraint_report[p] = {
        "position": p,
        "actual_letter": p_letter,
        "actual_value": p_val,
        "is_palette": p_val in PALETTE_VALS,
        "total_constraints": len(constraints),
        "unique_lags": len(lag_groups),
        "constraints": constraints,
    }

    status = "FORCED" if len(constraints) > 0 else "FREE"
    palette_tag = "PALETTE" if p_val in PALETTE_VALS else "NON-PALETTE"
    forced_palette = all(c["is_palette"] for c in constraints) if constraints else None

    print(f"  pos {p:2d} = {p_letter}({p_val:2d}) [{palette_tag}]: "
          f"{len(constraints)} constraints at {len(lag_groups)} distinct lags — {status}"
          + (f" (all forced vals palette: {forced_palette})" if constraints else ""))

    if constraints:
        for c in constraints[:5]:  # Show first 5
            print(f"    lag={c['lag']:2d} delta={c['delta']:2d}: "
                  f"{CT[c['left_pos']]}({c['left_pos']}) → "
                  f"{p_letter}({p}) → "
                  f"{CT[c['right_pos']]}({c['right_pos']})"
                  f"{'  [crib-anchored]' if c['left_is_crib'] or c['right_is_crib'] else ''}")
        if len(constraints) > 5:
            print(f"    ... and {len(constraints) - 5} more")

# ══════════════════════════════════════════════════════════════════════════
# T1.2: PALETTE COMPATIBILITY SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 70}")
print("T1.2: Palette Compatibility Summary")
print("-" * 50)

forced_positions = [p for p in NULL_POS if constraint_report[p]["total_constraints"] > 0]
free_positions = [p for p in NULL_POS if constraint_report[p]["total_constraints"] == 0]

print(f"  Forced positions: {len(forced_positions)}/{len(NULL_POS)} — {forced_positions}")
print(f"  Free positions:   {len(free_positions)}/{len(NULL_POS)} — {free_positions}")

all_palette_forced = True
for p in forced_positions:
    for c in constraint_report[p]["constraints"]:
        if not c["is_palette"]:
            all_palette_forced = False
            print(f"  WARNING: pos {p} has non-palette forced value at lag {c['lag']}")

if all_palette_forced and forced_positions:
    print(f"  ALL forced values are palette letters: YES")
else:
    print(f"  ALL forced values are palette letters: {'N/A' if not forced_positions else 'NO'}")


# ══════════════════════════════════════════════════════════════════════════
# T1.3: UNIQUENESS CHECK
# ══════════════════════════════════════════════════════════════════════════
# For each null position, how many of the 7 palette letters satisfy ALL
# constraints simultaneously?
print(f"\n{'=' * 70}")
print("T1.3: Uniqueness Check — Palette Letters Satisfying All Constraints")
print("-" * 50)

uniqueness_report = {}
for p in NULL_POS:
    info = constraint_report[p]
    if not info["constraints"]:
        uniqueness_report[p] = {
            "compatible_palette_count": 7,
            "compatible_palette_letters": PALETTE_LETTERS,
            "unique": False,
        }
        print(f"  pos {p:2d} = {CT[p]}: 7/7 palette letters work (no constraints)")
        continue

    # Collect all forced values from constraints
    forced_vals = set()
    for c in info["constraints"]:
        forced_vals.add(c["forced_val"])

    # All constraints at the same position must force the same value
    if len(forced_vals) == 1:
        fv = forced_vals.pop()
        compatible = [chr(fv + ord('A'))] if fv in PALETTE_VALS else []
        uniqueness_report[p] = {
            "compatible_palette_count": len(compatible),
            "compatible_palette_letters": compatible,
            "unique": len(compatible) == 1,
            "forced_value": fv,
        }
        tag = "UNIQUE" if len(compatible) == 1 else f"FORCED TO NON-PALETTE {chr(fv + ord('A'))}"
        print(f"  pos {p:2d} = {CT[p]}: {len(compatible)}/7 palette — {tag}")
    else:
        # Multiple constraints force DIFFERENT values — contradictory
        # This shouldn't happen since the actual CT satisfies all of them
        print(f"  pos {p:2d} = {CT[p]}: CONTRADICTORY constraints — forced vals: {forced_vals}")
        uniqueness_report[p] = {
            "compatible_palette_count": 0,
            "compatible_palette_letters": [],
            "unique": False,
            "contradiction": True,
        }


# ══════════════════════════════════════════════════════════════════════════
# T1.4: MONTE CARLO BASELINE
# ══════════════════════════════════════════════════════════════════════════
# How many constraints would we expect if null values were random letters?
print(f"\n{'=' * 70}")
print("T1.4: Monte Carlo Baseline — Expected Constraints Under Random")
print("-" * 50)

import random
random.seed(42)

N_TRIALS = 100_000
constraint_counts_random = []

for trial in range(N_TRIALS):
    # Replace null positions with random letters
    ct_rand = list(CT_NUM)
    for p in NULL_POS:
        ct_rand[p] = random.randint(0, 25)

    total_constraints = 0
    for p in NULL_POS:
        for d in range(1, 49):
            left = p - d
            right = p + d
            if (0 <= left < CT_LEN and left not in CONSENSUS_NULL_POSITIONS and
                0 <= right < CT_LEN and right not in CONSENSUS_NULL_POSITIONS):
                delta_l = (ct_rand[p] - ct_rand[left]) % MOD
                delta_r = (ct_rand[right] - ct_rand[p]) % MOD
                if delta_l == delta_r:
                    total_constraints += 1
    constraint_counts_random.append(total_constraints)

actual_total = sum(r["total_constraints"] for r in constraint_report.values())
mean_random = sum(constraint_counts_random) / N_TRIALS
exceeded = sum(1 for c in constraint_counts_random if c >= actual_total)
p_value = exceeded / N_TRIALS

print(f"  Actual total constraints: {actual_total}")
print(f"  Random mean: {mean_random:.2f}")
print(f"  Random max:  {max(constraint_counts_random)}")
print(f"  P(random >= actual): {p_value:.6f} ({exceeded}/{N_TRIALS})")
print(f"  Enrichment: {actual_total / mean_random:.2f}x" if mean_random > 0 else "  Enrichment: inf")


# ══════════════════════════════════════════════════════════════════════════
# T1.5: PALETTE-ONLY MONTE CARLO
# ══════════════════════════════════════════════════════════════════════════
# How many constraints if null values are random PALETTE letters (not any letter)?
print(f"\n{'=' * 70}")
print("T1.5: Palette-Only Baseline — Random Palette Letters at Null Positions")
print("-" * 50)

palette_list = sorted(PALETTE_VALS)
constraint_counts_palette = []

for trial in range(N_TRIALS):
    ct_pal = list(CT_NUM)
    for p in NULL_POS:
        ct_pal[p] = random.choice(palette_list)

    total_constraints = 0
    for p in NULL_POS:
        for d in range(1, 49):
            left = p - d
            right = p + d
            if (0 <= left < CT_LEN and left not in CONSENSUS_NULL_POSITIONS and
                0 <= right < CT_LEN and right not in CONSENSUS_NULL_POSITIONS):
                delta_l = (ct_pal[p] - ct_pal[left]) % MOD
                delta_r = (ct_pal[right] - ct_pal[p]) % MOD
                if delta_l == delta_r:
                    total_constraints += 1
    constraint_counts_palette.append(total_constraints)

mean_palette = sum(constraint_counts_palette) / N_TRIALS
exceeded_pal = sum(1 for c in constraint_counts_palette if c >= actual_total)
p_value_pal = exceeded_pal / N_TRIALS

print(f"  Actual total constraints: {actual_total}")
print(f"  Palette-random mean: {mean_palette:.2f}")
print(f"  Palette-random max:  {max(constraint_counts_palette)}")
print(f"  P(palette-random >= actual): {p_value_pal:.6f} ({exceeded_pal}/{N_TRIALS})")
print(f"  Enrichment: {actual_total / mean_palette:.2f}x" if mean_palette > 0 else "  Enrichment: inf")


# ══════════════════════════════════════════════════════════════════════════
# T1.6: STEHLE WINDOW DETAIL
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 70}")
print("T1.6: Stehle Window Detail (positions 55-63)")
print("-" * 50)

for i in range(55, 64):
    null_tag = "NULL" if i in CONSENSUS_NULL_POSITIONS else "real"
    crib_tag = f" CRIB({CRIB_DICT[i]})" if i in CRIB_POSITIONS else ""
    print(f"  pos {i}: {CT[i]}({CT_NUM[i]:2d}) [{null_tag}]{crib_tag}")
    if i >= 59:
        d4 = (CT_NUM[i] - CT_NUM[i-4]) % MOD
        print(f"         Δ4 from pos {i-4}: ({CT_NUM[i]} - {CT_NUM[i-4]}) mod 26 = {d4}")


# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 70}")
print("SUMMARY")
print("=" * 70)
print(f"  Null positions analyzed: {len(NULL_POS)}")
print(f"  Forced (≥1 constraint): {len(forced_positions)} — {forced_positions}")
print(f"  Free (0 constraints):   {len(free_positions)} — {free_positions}")
print(f"  Total constraints: {actual_total}")
print(f"  All forced values are palette: {all_palette_forced}")
print(f"  MC baseline (random): mean={mean_random:.2f}, P(>= actual)={p_value:.6f}")
print(f"  MC baseline (palette): mean={mean_palette:.2f}, P(>= actual)={p_value_pal:.6f}")

verdict = "SIGNIFICANT" if p_value < 0.01 else ("MODERATE" if p_value < 0.05 else "NOT SIGNIFICANT")
print(f"  VERDICT: {verdict}")

# ── Save artifact ──
os.makedirs(os.path.join(_ROOT, "results"), exist_ok=True)
artifact = {
    "experiment": "E-NULL-ARITHMETIC-CENSUS",
    "description": "Phase 1: Local constant-difference constraint census at all 17 null positions",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "null_positions": NULL_POS,
    "palette": PALETTE_LETTERS,
    "forced_positions": forced_positions,
    "free_positions": free_positions,
    "total_constraints": actual_total,
    "all_forced_palette": all_palette_forced,
    "mc_random_mean": round(mean_random, 2),
    "mc_random_pvalue": p_value,
    "mc_palette_mean": round(mean_palette, 2),
    "mc_palette_pvalue": p_value_pal,
    "verdict": verdict,
    "per_position": {
        str(p): {
            "letter": CT[p],
            "value": CT_NUM[p],
            "n_constraints": constraint_report[p]["total_constraints"],
            "n_lags": constraint_report[p]["unique_lags"],
            "constraints": constraint_report[p]["constraints"],
            "uniqueness": uniqueness_report.get(p, {}),
        }
        for p in NULL_POS
    },
}

outpath = os.path.join(_ROOT, "results", "null_arithmetic_constraint_census.json")
with open(outpath, "w") as f:
    json.dump(artifact, f, indent=2, default=str)
print(f"\n  Artifact saved: {outpath}")
