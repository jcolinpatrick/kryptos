#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort/VariantBeaufort (mixed)
Family: exploration
Status: active
Keyspace: 3^24 ~ 282B (pruned by Bean constraints)
Last run:
Best score:
"""
"""
E-MIXED-VARIANT-BEAN: Mixed-variant cipher Bean constraint enumeration

Hypothesis: K4 uses a MIXTURE of Vigenere, Beaufort, and Variant Beaufort
at different positions (not uniformly one variant). Each crib position has
3 possible key values (one per variant). Use Bean EQ/INEQ constraints to
prune via backtracking and enumerate all surviving variant assignments.

Strategy (3-phase):
  Phase 1: Constraint graph analysis — identify which positions are truly
           constrained, compute exact solution count via backtracking on
           the CONSTRAINED subgraph (21 positions, 39 INEQ edges + 1 EQ).
           Free positions (3) multiply by 3^3 = 27.
  Phase 2: Monte Carlo sampling — uniformly sample valid assignments,
           compute keystream properties (IC, distinct values, AP enrichment).
  Phase 3: Pattern detection — check all sampled solutions for positional
           patterns (mod N, CT-dependent, PT-dependent, grid-based).

Output: results/e_mixed_variant_bean.json
"""

import sys
import os
import json
import time
import random
from collections import Counter, defaultdict
from math import log2

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)

# ── Setup ────────────────────────────────────────────────────────────────────

POSITIONS = sorted(CRIB_DICT.keys())
N = len(POSITIONS)  # 24
POS_TO_IDX = {p: i for i, p in enumerate(POSITIONS)}

VARIANT_NAMES = ["vig", "beau", "vbeau"]

# Precompute key values: KEYS[idx][variant] = key_value (0..25)
KEYS = []
for pos in POSITIONS:
    ct_val = ALPH_IDX[CT[pos]]
    pt_val = ALPH_IDX[CRIB_DICT[pos]]
    KEYS.append([
        (ct_val - pt_val) % MOD,   # Vig
        (ct_val + pt_val) % MOD,   # Beau
        (pt_val - ct_val) % MOD,   # VBeau
    ])

# ── Build constraint graph ───────────────────────────────────────────────────

# Bean EQ: positions 27, 65 must use same variant
BEAN_EQ_IDX = [(POS_TO_IDX[a], POS_TO_IDX[b]) for a, b in BEAN_EQ]

# Bean INEQ: for each pair, find cross-variant collisions (forbidden combos)
# Store per-edge: FORBIDDEN_COMBOS[(ia, ib)] = set of (va, vb)
FORBIDDEN_COMBOS = {}
constraining_pairs = []

for a, b in BEAN_INEQ:
    ia, ib = POS_TO_IDX[a], POS_TO_IDX[b]
    forbidden = set()
    for va in range(3):
        for vb in range(3):
            if KEYS[ia][va] == KEYS[ib][vb]:
                forbidden.add((va, vb))
    if forbidden:
        FORBIDDEN_COMBOS[(ia, ib)] = forbidden
        constraining_pairs.append((ia, ib))

# Adjacency list: for each index, list of (neighbor_idx, edge_key)
# edge_key = (min_idx, max_idx) for lookup in FORBIDDEN_COMBOS
ADJ = defaultdict(list)
for ia, ib in constraining_pairs:
    ADJ[ia].append(ib)
    ADJ[ib].append(ia)

# Add EQ constraint edges
for ia, ib in BEAN_EQ_IDX:
    ADJ[ia].append(ib)
    ADJ[ib].append(ia)

# Identify constrained vs free positions
constrained_set = set()
for ia, ib in constraining_pairs:
    constrained_set.add(ia)
    constrained_set.add(ib)
for ia, ib in BEAN_EQ_IDX:
    constrained_set.add(ia)
    constrained_set.add(ib)

free_set = set(range(N)) - constrained_set
constrained_list = sorted(constrained_set)
free_list = sorted(free_set)

N_CONSTRAINED = len(constrained_list)
N_FREE = len(free_list)


def is_forbidden(ia, ib, va, vb):
    """Check if variant assignment (va at ia, vb at ib) is forbidden."""
    # Bean EQ check
    for ea, eb in BEAN_EQ_IDX:
        if (ia == ea and ib == eb) or (ia == eb and ib == ea):
            return va != vb  # Forbidden if different variants
    # Bean INEQ check
    key = (min(ia, ib), max(ia, ib))
    if key in FORBIDDEN_COMBOS:
        if ia <= ib:
            return (va, vb) in FORBIDDEN_COMBOS[key]
        else:
            return (vb, va) in FORBIDDEN_COMBOS[key]
    return False


# ── Phase 1: Exact counting on constrained subgraph ─────────────────────────

print("E-MIXED-VARIANT-BEAN: Mixed-variant cipher Bean constraint enumeration")
print("=" * 75)
print()
print(f"Crib positions ({N}): {POSITIONS}")
print(f"Bean EQ pairs: {len(BEAN_EQ)} (forces same variant at paired positions)")
print(f"Bean INEQ pairs: {len(BEAN_INEQ)} total, {len(constraining_pairs)} with "
      f"cross-variant collisions")
print(f"Theoretical space: 3^{N} = {3**N:,}")
print()

# Show key values at each position
print("Key values at crib positions:")
print(f"{'Pos':>4s} {'CT':>3s} {'PT':>3s} {'Vig':>5s} {'Beau':>5s} {'VBeau':>5s}  {'Status'}")
print("-" * 55)
for i, pos in enumerate(POSITIONS):
    kv = KEYS[i]
    status = "FREE" if i in free_set else "constrained"
    print(f"{pos:4d} {CT[pos]:>3s} {CRIB_DICT[pos]:>3s} "
          f"{kv[0]:2d}({ALPH[kv[0]]}) "
          f"{kv[1]:2d}({ALPH[kv[1]]}) "
          f"{kv[2]:2d}({ALPH[kv[2]]})  {status}")
print()

print(f"Constrained positions: {N_CONSTRAINED} "
      f"({[POSITIONS[i] for i in constrained_list]})")
print(f"Free positions: {N_FREE} ({[POSITIONS[i] for i in free_list]})")
print(f"Free positions contribute factor: 3^{N_FREE} = {3**N_FREE}")
print()

# Show forbidden combos detail
print("Constraining INEQ edges (cross-variant collisions):")
for ia, ib in constraining_pairs:
    fc = FORBIDDEN_COMBOS[(ia, ib)]
    fc_str = ", ".join(f"({VARIANT_NAMES[va]}@{POSITIONS[ia]},"
                       f"{VARIANT_NAMES[vb]}@{POSITIONS[ib]})"
                       for va, vb in sorted(fc))
    print(f"  ({POSITIONS[ia]:2d},{POSITIONS[ib]:2d}): {len(fc)} forbidden: {fc_str}")
print()

# Backtracking on constrained subgraph
# Order: most-constrained first within the constrained set
degree = Counter()
for ia, ib in constraining_pairs:
    degree[ia] += 1
    degree[ib] += 1
for ia, ib in BEAN_EQ_IDX:
    degree[ia] += 5  # EQ is a strong constraint
    degree[ib] += 5

ORDER = sorted(constrained_list, key=lambda i: -degree.get(i, 0))

assignment = [-1] * N
solution_count = 0
nodes_explored = 0

# For sampling: collect solutions (up to a limit) and count the rest
MAX_STORE = 100_000  # Store up to 100K solutions for analysis
stored_solutions = []


def check_constrained(idx, variant):
    """Check if assigning variant at idx is consistent with current partial assignment."""
    # Bean EQ
    for ea, eb in BEAN_EQ_IDX:
        if idx == ea and assignment[eb] != -1:
            if assignment[eb] != variant:
                return False
        elif idx == eb and assignment[ea] != -1:
            if assignment[ea] != variant:
                return False

    # Bean INEQ (only check assigned neighbors)
    for nb in ADJ[idx]:
        if assignment[nb] == -1:
            continue
        if is_forbidden(idx, nb, variant, assignment[nb]):
            return False

    return True


def count_solutions(depth):
    """Count (and optionally store) all valid assignments on constrained subgraph."""
    global solution_count, nodes_explored

    if depth == N_CONSTRAINED:
        solution_count += 1
        if len(stored_solutions) < MAX_STORE:
            sol = list(assignment)
            stored_solutions.append(sol)
        return

    idx = ORDER[depth]
    for variant in range(3):
        nodes_explored += 1
        if check_constrained(idx, variant):
            assignment[idx] = variant
            count_solutions(depth + 1)
            assignment[idx] = -1


print("Phase 1: Exact counting on constrained subgraph...")
print(f"Processing order: {[POSITIONS[i] for i in ORDER]}")
t0 = time.time()
count_solutions(0)
elapsed_phase1 = time.time() - t0

# Total solutions = constrained solutions * 3^free
total_solutions = solution_count * (3 ** N_FREE)

print(f"\nPhase 1 complete in {elapsed_phase1:.2f}s")
print(f"Constrained subgraph solutions: {solution_count:,}")
print(f"Free multiplier: 3^{N_FREE} = {3**N_FREE}")
print(f"TOTAL solutions: {total_solutions:,}")
print(f"Out of 3^{N} = {3**N:,}")
print(f"Survival rate: {total_solutions / 3**N * 100:.4f}%")
print(f"Reduction: {3**N / total_solutions:.2f}x")
print(f"Nodes explored: {nodes_explored:,}")
print(f"Solutions stored for analysis: {len(stored_solutions):,}")
print()

# ── Phase 2: Expand stored solutions with random free-position assignments ──

print("Phase 2: Keystream property analysis...")

# For each stored constrained solution, generate a few random
# free-position assignments and analyze
N_SAMPLES_PER_SOL = max(1, min(10, 50_000 // max(len(stored_solutions), 1)))
if N_FREE == 0:
    N_SAMPLES_PER_SOL = 1

random.seed(20260321)  # Reproducible
analysis_results = []

for sol in stored_solutions:
    for _ in range(N_SAMPLES_PER_SOL):
        # Fill in free positions randomly
        full_sol = list(sol)
        for fi in free_list:
            full_sol[fi] = random.randint(0, 2)

        # Compute keystream
        keystream = [KEYS[i][full_sol[i]] for i in range(N)]

        # IC of keystream
        freq = Counter(keystream)
        ic_num = sum(f * (f - 1) for f in freq.values())
        ic_den = N * (N - 1) if N > 1 else 1
        ic = ic_num / ic_den

        # Distinct key values
        n_distinct = len(freq)

        # AP enrichment: how many in {G=6, K=10, O=14}?
        ap_set = {6, 10, 14}
        ap_count = sum(1 for k in keystream if k in ap_set)

        # Variant pattern
        variant_set = set(full_sol)
        is_pure = len(variant_set) == 1

        # Variant pattern string (V=Vig, B=Beau, X=VBeau)
        vpattern = "".join(["V", "B", "X"][v] for v in full_sol)

        # Position mod-N patterns
        mod_patterns = {}
        for m in range(2, 8):
            residue_variants = defaultdict(set)
            for i, v in enumerate(full_sol):
                pos = POSITIONS[i]
                residue_variants[pos % m].add(v)
            uniform = all(len(vs) == 1 for vs in residue_variants.values())
            if uniform:
                mod_patterns[m] = {r: list(vs)[0] for r, vs in residue_variants.items()}

        # CT-letter-dependent
        ct_letter_variants = defaultdict(set)
        for i, v in enumerate(full_sol):
            ct_letter_variants[CT[POSITIONS[i]]].add(v)
        ct_uniform = all(len(vs) == 1 for vs in ct_letter_variants.values())

        # PT-letter-dependent
        pt_letter_variants = defaultdict(set)
        for i, v in enumerate(full_sol):
            pt_letter_variants[CRIB_DICT[POSITIONS[i]]].add(v)
        pt_uniform = all(len(vs) == 1 for vs in pt_letter_variants.values())

        # 7x14 grid patterns
        grid_row_variants = defaultdict(set)
        grid_col_variants = defaultdict(set)
        for i, v in enumerate(full_sol):
            pos = POSITIONS[i]
            grid_row_variants[pos // 14].add(v)
            grid_col_variants[pos % 14].add(v)
        grid_row_uniform = all(len(vs) == 1 for vs in grid_row_variants.values())
        grid_col_uniform = all(len(vs) == 1 for vs in grid_col_variants.values())

        analysis_results.append({
            "variant_assignment": full_sol,
            "variant_pattern": vpattern,
            "keystream": keystream,
            "keystream_letters": "".join(ALPH[k] for k in keystream),
            "ic": ic,
            "n_distinct": n_distinct,
            "ap_count": ap_count,
            "is_pure": is_pure,
            "variants_used": sorted(variant_set),
            "mod_patterns": mod_patterns,
            "ct_uniform": ct_uniform,
            "pt_uniform": pt_uniform,
            "grid_row_uniform": grid_row_uniform,
            "grid_col_uniform": grid_col_uniform,
        })

n_analyzed = len(analysis_results)
print(f"Analyzed {n_analyzed:,} full assignments "
      f"({len(stored_solutions)} constrained * {N_SAMPLES_PER_SOL} free combos)")
print()

# ── Phase 3: Pattern detection and statistics ────────────────────────────────

print("Phase 3: Statistical analysis")
print("=" * 75)
print()

# Pure vs mixed
pure_counts = {"vig": 0, "beau": 0, "vbeau": 0}
mixed_count = 0
for r in analysis_results:
    if r["is_pure"]:
        pure_counts[VARIANT_NAMES[r["variant_assignment"][0]]] += 1
    else:
        mixed_count += 1

print(f"Pure Vig:   {pure_counts['vig']:,}")
print(f"Pure Beau:  {pure_counts['beau']:,}")
print(f"Pure VBeau: {pure_counts['vbeau']:,}")
print(f"Mixed:      {mixed_count:,}")
total_pure = sum(pure_counts.values())
print(f"Pure total: {total_pure:,} ({total_pure/n_analyzed*100:.2f}%)")
print(f"Mixed total: {mixed_count:,} ({mixed_count/n_analyzed*100:.2f}%)")
print()

# Are all 3 pure-variant solutions present?
print("Pure-variant keystreams (the 3 standard solutions):")
for vname, vidx in [("vig", 0), ("beau", 1), ("vbeau", 2)]:
    ks = [KEYS[i][vidx] for i in range(N)]
    ks_str = "".join(ALPH[k] for k in ks)
    freq = Counter(ks)
    ic_num = sum(f * (f - 1) for f in freq.values())
    ic = ic_num / (N * (N - 1))
    n_dist = len(freq)
    ap_count = sum(1 for k in ks if k in {6, 10, 14})
    print(f"  {vname:6s}: {ks_str} | IC={ic:.4f} | distinct={n_dist} | AP={ap_count}/24")
print()

# IC distribution
ics = [r["ic"] for r in analysis_results]
print(f"IC distribution across {n_analyzed:,} samples:")
print(f"  min={min(ics):.4f}, max={max(ics):.4f}, mean={sum(ics)/len(ics):.4f}")
ic_bins = [(0, 0.02), (0.02, 0.03), (0.03, 0.04), (0.04, 0.05),
           (0.05, 0.06), (0.06, 0.08), (0.08, 0.10), (0.10, 0.15),
           (0.15, 0.20), (0.20, 1.0)]
for lo, hi in ic_bins:
    count = sum(1 for x in ics if lo <= x < hi)
    if count > 0:
        print(f"  [{lo:.2f}, {hi:.2f}): {count:,} ({count/n_analyzed*100:.1f}%)")
print()

# Distinct values distribution
distincts = [r["n_distinct"] for r in analysis_results]
dist_counts = Counter(distincts)
print("Distinct key values distribution:")
for d in sorted(dist_counts.keys()):
    print(f"  {d:2d} distinct: {dist_counts[d]:,} ({dist_counts[d]/n_analyzed*100:.1f}%)")
print()

# AP enrichment
aps = [r["ap_count"] for r in analysis_results]
ap_dist = Counter(aps)
print("AP {G,K,O} enrichment distribution:")
for a in sorted(ap_dist.keys()):
    print(f"  {a:2d}/24: {ap_dist[a]:,} ({ap_dist[a]/n_analyzed*100:.1f}%)")
# Expected AP under random: each position has 3/26 chance of hitting {G,K,O}
# But here each position has fixed values under each variant
# Compute: what fraction of position-variant combos land in AP set?
ap_positions = 0
for i in range(N):
    for v in range(3):
        if KEYS[i][v] in {6, 10, 14}:
            ap_positions += 1
print(f"\n  Per-position AP availability: {ap_positions}/{N*3} = "
      f"{ap_positions/(N*3)*100:.1f}% of (position,variant) combos")
print(f"  Expected AP if uniform random variant: {ap_positions/3:.1f}/24")
# Known Beaufort has AP = 12/24
print(f"  Known Beaufort AP: 12/24 (50%)")
print()

# Positional pattern analysis
mod_solutions = [r for r in analysis_results if r["mod_patterns"]]
print(f"Solutions with pos%N uniformity (variant same within each residue class):")
print(f"  Total: {len(mod_solutions):,} / {n_analyzed:,}")
if mod_solutions:
    mod_counts = Counter()
    for r in mod_solutions:
        for m in r["mod_patterns"]:
            mod_counts[m] += 1
    for m in sorted(mod_counts.keys()):
        print(f"  mod {m}: {mod_counts[m]:,} solutions")
    # Show first few
    for r in mod_solutions[:5]:
        for m, pattern in r["mod_patterns"].items():
            pat_str = ", ".join(f"r{k}={VARIANT_NAMES[v]}"
                                for k, v in sorted(pattern.items()))
            print(f"    mod {m}: {pat_str} | ks={r['keystream_letters']} | "
                  f"IC={r['ic']:.4f}")
print()

ct_solutions = [r for r in analysis_results if r["ct_uniform"]]
print(f"Solutions with CT-letter-uniform variants: "
      f"{len(ct_solutions):,} / {n_analyzed:,}")
for r in ct_solutions[:5]:
    print(f"  ks={r['keystream_letters']} | IC={r['ic']:.4f} | AP={r['ap_count']}/24")
print()

pt_solutions = [r for r in analysis_results if r["pt_uniform"]]
print(f"Solutions with PT-letter-uniform variants: "
      f"{len(pt_solutions):,} / {n_analyzed:,}")
for r in pt_solutions[:5]:
    print(f"  ks={r['keystream_letters']} | IC={r['ic']:.4f} | AP={r['ap_count']}/24")
print()

grid_row_solutions = [r for r in analysis_results if r["grid_row_uniform"]]
print(f"Solutions with 7x14 grid ROW-uniform: "
      f"{len(grid_row_solutions):,} / {n_analyzed:,}")
for r in grid_row_solutions[:5]:
    print(f"  vp={r['variant_pattern']} | ks={r['keystream_letters']} | "
          f"IC={r['ic']:.4f}")
print()

grid_col_solutions = [r for r in analysis_results if r["grid_col_uniform"]]
print(f"Solutions with 7x14 grid COL-uniform: "
      f"{len(grid_col_solutions):,} / {n_analyzed:,}")
for r in grid_col_solutions[:5]:
    print(f"  vp={r['variant_pattern']} | ks={r['keystream_letters']} | "
          f"IC={r['ic']:.4f}")
print()

# Top solutions by various criteria
print("Top 15 by LOWEST IC (most random/high-entropy keystream):")
sorted_by_ic = sorted(analysis_results, key=lambda r: r["ic"])
for r in sorted_by_ic[:15]:
    print(f"  IC={r['ic']:.4f} | distinct={r['n_distinct']} | "
          f"AP={r['ap_count']}/24 | ks={r['keystream_letters']} | "
          f"vp={r['variant_pattern']}")
print()

print("Top 15 by HIGHEST AP enrichment:")
sorted_by_ap = sorted(analysis_results, key=lambda r: (-r["ap_count"], r["ic"]))
for r in sorted_by_ap[:15]:
    print(f"  AP={r['ap_count']}/24 | IC={r['ic']:.4f} | "
          f"distinct={r['n_distinct']} | ks={r['keystream_letters']} | "
          f"vp={r['variant_pattern']}")
print()

print("Top 15 by FEWEST distinct key values:")
sorted_by_distinct = sorted(analysis_results, key=lambda r: (r["n_distinct"], -r["ic"]))
for r in sorted_by_distinct[:15]:
    print(f"  distinct={r['n_distinct']} | IC={r['ic']:.4f} | "
          f"AP={r['ap_count']}/24 | ks={r['keystream_letters']} | "
          f"vp={r['variant_pattern']}")
print()

# Check: do any solutions match the known Beaufort keystream?
beau_ks = [KEYS[i][1] for i in range(N)]  # Pure Beaufort keystream
beau_match = [r for r in analysis_results if r["keystream"] == beau_ks]
print(f"Solutions matching pure Beaufort keystream: {len(beau_match)}")
if beau_match:
    for r in beau_match[:3]:
        print(f"  vp={r['variant_pattern']} (pure={'yes' if r['is_pure'] else 'no'})")
print()

# Variant frequency at each constrained position
print("Variant frequency at each position (across stored constrained solutions):")
for i, pos in enumerate(POSITIONS):
    v_counts = Counter(sol[i] for sol in stored_solutions)
    total = sum(v_counts.values())
    parts = []
    for v in range(3):
        pct = v_counts.get(v, 0) / total * 100
        parts.append(f"{VARIANT_NAMES[v]}={pct:.1f}%")
    constraint_label = "FREE" if i in free_set else ""
    print(f"  pos {pos:2d}: {', '.join(parts)}  {constraint_label}")
print()

# Key insight: positions where one variant dominates (>90%)
print("Highly constrained positions (one variant >80%):")
for i, pos in enumerate(POSITIONS):
    if i in free_set:
        continue
    v_counts = Counter(sol[i] for sol in stored_solutions)
    total = sum(v_counts.values())
    for v in range(3):
        pct = v_counts.get(v, 0) / total * 100
        if pct > 80:
            print(f"  pos {pos:2d}: {VARIANT_NAMES[v]} dominates at {pct:.1f}%")
print()

# ── Compare mixed-variant constraints to standard single-variant ─────────────

print("=" * 75)
print("COMPARISON: Mixed vs Pure Variant Constraint Strength")
print("=" * 75)
print()

# Under pure variant, how many assignments survive?
# Pure = 3 (one for each variant)
# Under mixed with Bean, we get solution_count * 3^N_FREE
# Ratio = (total_solutions) / 3 = how much more permissive is mixed?
print(f"Pure single-variant: 3 valid assignments")
print(f"Mixed-variant + Bean: {total_solutions:,} valid assignments")
print(f"Mixed is {total_solutions / 3:.0f}x more permissive than pure")
print(f"As fraction of full space: {total_solutions / 3**N * 100:.4f}%")
print(f"Bits of freedom: {log2(total_solutions):.1f} (vs {log2(3):.1f} pure, "
      f"{N * log2(3):.1f} unconstrained)")
print()

# ── Summary verdict ──────────────────────────────────────────────────────────

print("=" * 75)
print("VERDICT")
print("=" * 75)
print()

if total_solutions <= 3:
    verdict = ("Bean constraints reduce mixed-variant to pure-variant. "
               "No advantage from mixing.")
    classification = "ELIMINATED"
elif total_solutions > 1_000_000:
    verdict = (f"Bean constraints are WEAK for mixed variants: "
               f"{total_solutions:,} valid assignments survive "
               f"(only {3**N // total_solutions:.0f}x reduction). "
               f"The search space remains enormous. "
               f"Mixed variants are technically FEASIBLE but the Bean constraints "
               f"provide almost no discrimination.")
    classification = "FEASIBLE_BUT_WEAK"
else:
    verdict = (f"{total_solutions:,} assignments survive. "
               f"Bean constraints provide moderate filtering. "
               f"Further analysis needed.")
    classification = "MODERATE"

print(f"Classification: {classification}")
print(f"Verdict: {verdict}")
print()

# ── Save results ─────────────────────────────────────────────────────────────

output = {
    "experiment": "e_mixed_variant_bean",
    "description": "Mixed-variant cipher Bean constraint enumeration",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "parameters": {
        "n_positions": N,
        "n_bean_eq": len(BEAN_EQ),
        "n_bean_ineq": len(BEAN_INEQ),
        "n_constraining_ineq": len(constraining_pairs),
        "theoretical_space": 3**N,
        "n_constrained_positions": N_CONSTRAINED,
        "n_free_positions": N_FREE,
        "free_positions": [POSITIONS[i] for i in free_list],
        "constrained_positions": [POSITIONS[i] for i in constrained_list],
    },
    "phase1_counting": {
        "constrained_solutions": solution_count,
        "free_multiplier": 3**N_FREE,
        "total_solutions": total_solutions,
        "survival_rate_pct": total_solutions / 3**N * 100,
        "reduction_factor": 3**N / total_solutions if total_solutions > 0 else float('inf'),
        "bits_of_freedom": log2(total_solutions) if total_solutions > 0 else 0,
        "elapsed_seconds": elapsed_phase1,
        "nodes_explored": nodes_explored,
        "stored_solutions": len(stored_solutions),
    },
    "phase2_analysis": {
        "samples_analyzed": n_analyzed,
        "pure_counts": pure_counts,
        "mixed_count": mixed_count,
        "ic_stats": {
            "min": min(ics),
            "max": max(ics),
            "mean": sum(ics) / len(ics),
        },
        "distinct_stats": {
            str(k): v for k, v in sorted(dist_counts.items())
        },
        "ap_stats": {
            str(k): v for k, v in sorted(ap_dist.items())
        },
    },
    "phase3_patterns": {
        "pos_mod_N_uniform": len(mod_solutions),
        "ct_letter_uniform": len(ct_solutions),
        "pt_letter_uniform": len(pt_solutions),
        "grid_row_uniform": len(grid_row_solutions),
        "grid_col_uniform": len(grid_col_solutions),
    },
    "sample_solutions": {
        "lowest_ic": [
            {"vp": r["variant_pattern"], "ks": r["keystream_letters"],
             "ic": r["ic"], "ap": r["ap_count"], "dist": r["n_distinct"]}
            for r in sorted_by_ic[:25]
        ],
        "highest_ap": [
            {"vp": r["variant_pattern"], "ks": r["keystream_letters"],
             "ic": r["ic"], "ap": r["ap_count"], "dist": r["n_distinct"]}
            for r in sorted_by_ap[:25]
        ],
        "fewest_distinct": [
            {"vp": r["variant_pattern"], "ks": r["keystream_letters"],
             "ic": r["ic"], "ap": r["ap_count"], "dist": r["n_distinct"]}
            for r in sorted_by_distinct[:25]
        ],
    },
    "classification": classification,
    "conclusion": verdict,
}

results_path = os.path.join(_ROOT, "results", "e_mixed_variant_bean.json")
os.makedirs(os.path.dirname(results_path), exist_ok=True)
with open(results_path, "w") as f:
    json.dump(output, f, indent=2)

print(f"Results saved to {results_path}")
