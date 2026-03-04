#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-CHART-09: Exhaustive boundary sweep — 2-letter insertions near BERLINCLOCK.

Context: E-CHART-07 found best scores when inserting characters near positions 61-63
(just before BERLINCLOCK crib at 63-73). This experiment determines whether that
region is genuinely special or an artifact.

Phase 1: For each position 50-75, insert CC, test ALL 362,880 w9 orderings.
         26 positions x 362,880 = 9.4M checks. Maps the score landscape.

Phase 2: For top 3 positions from Phase 1, test ALL 676 letter pairs (AA-ZZ)
         with top 1000 orderings from Phase 1. 3 x 676 x 1000 = 2.0M checks.

Phase 3: Non-consecutive insertion -- one char at pos i, another at pos j (i!=j),
         both in range 55-70. C(16,2)=120 pairs x 6 letter pairs x top 1000 orderings
         = 720K checks.

Scoring: After decrypting the 99-char text, REMOVE the 2 inserted chars from
         the result at the same positions, then score the 97-char text against cribs.
"""
import json
import itertools
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, N_CRIBS

# -- Precompute crib arrays for fast scoring --
CRIB_POSITIONS_LIST = sorted(CRIB_DICT.keys())
CRIB_CHARS = [CRIB_DICT[p] for p in CRIB_POSITIONS_LIST]
N_CRIB = len(CRIB_POSITIONS_LIST)

# Convert CT to integer array for faster operations
ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
CT_ARR = list(CT)


def precompute_w9_perm_99(order):
    """For a 99-char text with width=9, all columns have length 11.
    Return perm where perm[pt_pos] = ct_pos (gather convention)."""
    col_starts = [0] * 9
    pos = 0
    for rank in range(9):
        col_idx = order[rank]
        col_starts[col_idx] = pos
        pos += 11
    perm = []
    for row in range(11):
        for col in range(9):
            perm.append(col_starts[col] + row)
    return perm


def precompute_all_perms():
    """Precompute all 9! permutations and their inverse mappings."""
    all_perms = []
    all_inv = []  # inv[ct_pos] = pt_pos
    for order in itertools.permutations(range(9)):
        perm = precompute_w9_perm_99(order)
        inv = [0] * 99
        for pt_pos in range(99):
            inv[perm[pt_pos]] = pt_pos
        all_perms.append(perm)
        all_inv.append(inv)
    return all_perms, all_inv


def score_consecutive_fast(extended, perm, inv, insert_pos):
    """Score a 99-char extended CT after columnar decrypt + removal of 2 inserted chars.

    Args:
        extended: 99-char extended ciphertext (list or string)
        perm: perm[pt_pos] = ct_pos
        inv: inv[ct_pos] = pt_pos (inverse of perm)
        insert_pos: where the 2 chars were inserted in the CT

    Returns:
        crib match count (0-24)
    """
    # The 2 inserted CT positions are insert_pos and insert_pos+1
    # These map to PT positions inv[insert_pos] and inv[insert_pos+1]
    rm_a = inv[insert_pos]
    rm_b = inv[insert_pos + 1]

    # Ensure rm_a < rm_b for consistent removal order
    if rm_a > rm_b:
        rm_a, rm_b = rm_b, rm_a

    # For each crib position p97 in the 97-char text, compute the corresponding
    # position in the 99-char text:
    # If p97 < rm_a: pt99_pos = p97
    # If rm_a <= p97 < rm_b - 1: pt99_pos = p97 + 1
    # If p97 >= rm_b - 1: pt99_pos = p97 + 2
    score = 0
    for idx in range(N_CRIB):
        p97 = CRIB_POSITIONS_LIST[idx]
        if p97 < rm_a:
            pt99_pos = p97
        elif p97 < rm_b - 1:
            pt99_pos = p97 + 1
        else:
            pt99_pos = p97 + 2
        ct99_pos = perm[pt99_pos]
        if extended[ct99_pos] == CRIB_CHARS[idx]:
            score += 1
    return score


def get_pt97_from_consecutive(extended, perm, inv, insert_pos):
    """Get the 97-char plaintext after removing inserted positions."""
    rm_a = inv[insert_pos]
    rm_b = inv[insert_pos + 1]
    remove_set = {rm_a, rm_b}
    pt99 = [extended[perm[i]] for i in range(99)]
    pt97 = [pt99[i] for i in range(99) if i not in remove_set]
    return ''.join(pt97)


print("=" * 70)
print("E-CHART-09: Exhaustive Boundary Sweep - Insertions near BERLINCLOCK")
print("=" * 70)
print(f"CT length: {CT_LEN}")
print(f"Cribs: ENE@21-33 (13 chars), BC@63-73 (11 chars)")
print(f"Width: 9, 99 chars = 9x11 grid (all columns equal)")
print()

t0 = time.time()

# Precompute all permutations
print("Precomputing all 362,880 w9 permutations and inverses...")
ALL_PERMS, ALL_INV = precompute_all_perms()
print(f"  Done in {time.time() - t0:.1f}s")

results = {
    'experiment': 'E-CHART-09',
    'description': 'Exhaustive boundary sweep: 2-letter insertions near BERLINCLOCK with w9 transposition',
    'phases': {}
}

# =====================================================================
# PHASE 1: CC insertion at positions 50-75, ALL 362,880 w9 orderings
# =====================================================================
print("\n" + "=" * 70)
print("PHASE 1: CC insertion at positions 50-75, ALL 9! orderings")
print("=" * 70)

PHASE1_RANGE = range(50, 76)
N_PERMS = 362880

phase1_results = {}
phase1_top_orderings = {}  # position -> list of (perm_idx, score) sorted desc

total_checks = len(PHASE1_RANGE) * N_PERMS
checked = 0
t1_start = time.time()

for insert_pos in PHASE1_RANGE:
    # Build extended CT once per position
    extended = CT[:insert_pos] + 'CC' + CT[insert_pos:]
    ext_list = list(extended)

    pos_best_score = 0
    pos_best_idx = 0
    pos_score_dist = defaultdict(int)
    pos_order_scores = []

    for perm_idx in range(N_PERMS):
        perm = ALL_PERMS[perm_idx]
        inv = ALL_INV[perm_idx]
        sc = score_consecutive_fast(ext_list, perm, inv, insert_pos)
        pos_score_dist[sc] += 1
        pos_order_scores.append((perm_idx, sc))

        if sc > pos_best_score:
            pos_best_score = sc
            pos_best_idx = perm_idx

        checked += 1

    # Sort orderings by score descending and keep top 1000
    pos_order_scores.sort(key=lambda x: -x[1])
    phase1_top_orderings[insert_pos] = pos_order_scores[:1000]

    # Get best PT for reporting
    best_perm = ALL_PERMS[pos_best_idx]
    best_inv = ALL_INV[pos_best_idx]
    best_pt = get_pt97_from_consecutive(ext_list, best_perm, best_inv, insert_pos)

    # Reconstruct the order from the perm index
    all_orders_list = list(itertools.permutations(range(9)))
    best_order = list(all_orders_list[pos_best_idx])

    phase1_results[insert_pos] = {
        'best_score': pos_best_score,
        'best_order': best_order,
        'best_pt_preview': best_pt[:80],
        'score_dist': dict(pos_score_dist),
        'mean_score': sum(k * v for k, v in pos_score_dist.items()) / N_PERMS,
    }

    elapsed = time.time() - t1_start
    rate = checked / elapsed if elapsed > 0 else 0
    remaining = (total_checks - checked) / rate if rate > 0 else 0
    print(f"  pos={insert_pos:3d}: best={pos_best_score:2d}/24, "
          f"mean={phase1_results[insert_pos]['mean_score']:.2f}, "
          f"order={best_order}, "
          f"[{checked:,}/{total_checks:,}, {rate:.0f}/s, ETA {remaining:.0f}s]")

# Print heat map
print("\n--- Phase 1 Score Landscape (position vs best score) ---")
print("  Pos  Best  Mean   Histogram")
print("  ---  ----  -----  ---------")
sorted_positions = sorted(phase1_results.items(), key=lambda x: -x[1]['best_score'])
for pos in sorted(phase1_results.keys()):
    info = phase1_results[pos]
    bar = "#" * info['best_score']
    print(f"  {pos:3d}  {info['best_score']:4d}  {info['mean_score']:5.2f}  {bar}")

# Top 3 positions
top3_positions = [p for p, _ in sorted_positions[:3]]
print(f"\n  Top 3 positions: {top3_positions}")
for p in top3_positions:
    info = phase1_results[p]
    print(f"    pos={p}: best={info['best_score']}/24, mean={info['mean_score']:.2f}")
    print(f"      order={info['best_order']}")
    print(f"      PT: {info['best_pt_preview']}")

results['phases']['phase1'] = {
    'description': 'CC insertion at each position 50-75, all 362880 w9 orderings',
    'total_checks': total_checks,
    'time_seconds': time.time() - t1_start,
    'position_results': {str(k): {
        'best_score': v['best_score'],
        'best_order': v['best_order'],
        'best_pt_preview': v['best_pt_preview'],
        'mean_score': v['mean_score'],
    } for k, v in phase1_results.items()},
    'top3_positions': top3_positions,
}

phase1_time = time.time() - t1_start
print(f"\n  Phase 1 complete: {total_checks:,} checks in {phase1_time:.1f}s "
      f"({total_checks/phase1_time:.0f}/s)")

# =====================================================================
# PHASE 2: Top 3 positions, ALL 676 letter pairs, top 1000 orderings
# =====================================================================
print("\n" + "=" * 70)
print("PHASE 2: Top 3 positions x 676 letter pairs x top 1000 orderings")
print("=" * 70)

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
t2_start = time.time()

phase2_results = {}
total_p2 = len(top3_positions) * 676 * 1000
checked_p2 = 0

for insert_pos in top3_positions:
    pos_results = {}
    pos_global_best = 0
    pos_global_pair = ""
    pos_global_order = None
    pos_global_pt = ""

    # Get top 1000 perm indices for this position
    top_perm_indices = [idx for idx, _ in phase1_top_orderings[insert_pos]]

    for c1 in ALPHABET:
        for c2 in ALPHABET:
            pair_label = c1 + c2
            pair_best = 0
            pair_best_perm_idx = 0

            # Build extended CT once per pair
            extended = list(CT[:insert_pos] + c1 + c2 + CT[insert_pos:])

            for perm_idx in top_perm_indices:
                perm = ALL_PERMS[perm_idx]
                inv = ALL_INV[perm_idx]
                sc = score_consecutive_fast(extended, perm, inv, insert_pos)
                checked_p2 += 1

                if sc > pair_best:
                    pair_best = sc
                    pair_best_perm_idx = perm_idx

            pos_results[pair_label] = pair_best

            if pair_best > pos_global_best:
                pos_global_best = pair_best
                pos_global_pair = pair_label
                pos_global_order = list(list(itertools.permutations(range(9)))[pair_best_perm_idx])
                pos_global_pt = get_pt97_from_consecutive(
                    extended, ALL_PERMS[pair_best_perm_idx],
                    ALL_INV[pair_best_perm_idx], insert_pos)

    # Sort pairs by score
    sorted_pairs = sorted(pos_results.items(), key=lambda x: -x[1])
    top10_pairs = sorted_pairs[:10]

    print(f"\n  Position {insert_pos}: best pair={pos_global_pair}, "
          f"score={pos_global_best}/24")
    print(f"  Top 10 letter pairs:")
    for pair, sc in top10_pairs:
        print(f"    {pair}: {sc}/24")

    phase2_results[insert_pos] = {
        'best_score': pos_global_best,
        'best_pair': pos_global_pair,
        'best_order': pos_global_order,
        'best_pt_preview': pos_global_pt[:80] if pos_global_pt else "",
        'top10_pairs': top10_pairs,
    }

    elapsed_p2 = time.time() - t2_start
    rate_p2 = checked_p2 / elapsed_p2 if elapsed_p2 > 0 else 0
    remaining_p2 = (total_p2 - checked_p2) / rate_p2 if rate_p2 > 0 else 0
    print(f"  [{checked_p2:,}/{total_p2:,}, {rate_p2:.0f}/s, ETA {remaining_p2:.0f}s]")

results['phases']['phase2'] = {
    'description': 'Top 3 positions x 676 pairs x top 1000 orderings',
    'total_checks': checked_p2,
    'time_seconds': time.time() - t2_start,
    'position_results': {str(k): {
        'best_score': v['best_score'],
        'best_pair': v['best_pair'],
        'best_order': v['best_order'],
        'best_pt_preview': v['best_pt_preview'],
        'top10_pairs': v['top10_pairs'],
    } for k, v in phase2_results.items()},
}

phase2_time = time.time() - t2_start
print(f"\n  Phase 2 complete: {checked_p2:,} checks in {phase2_time:.1f}s")

# =====================================================================
# PHASE 3: Non-consecutive insertion in range 55-70
# =====================================================================
print("\n" + "=" * 70)
print("PHASE 3: Non-consecutive insertion in range 55-70")
print("=" * 70)

NC_RANGE = range(55, 71)
NC_LETTER_PAIRS = [('C', 'C'), ('Y', 'R'), ('Y', 'A'), ('A', 'R'), ('L', 'L'), ('E', 'E')]
t3_start = time.time()

# Use top 1000 orderings from the best Phase 1 position
best_p1_pos = top3_positions[0]
global_top_perm_indices = [idx for idx, _ in phase1_top_orderings[best_p1_pos]]

phase3_results = {}
phase3_global_best = 0
checked_p3 = 0

nc_positions = [(i, j) for i in NC_RANGE for j in NC_RANGE if i < j]
total_p3 = len(nc_positions) * len(NC_LETTER_PAIRS) * 1000
print(f"  {len(nc_positions)} position pairs x {len(NC_LETTER_PAIRS)} letter pairs x 1000 orderings = {total_p3:,} checks")


def score_nonconsec_fast(ct_original, pos_i, pos_j, c1, c2, perm, inv):
    """Insert c1 at pos_i and c2 at pos_j in the ORIGINAL 97-char CT.
    pos_i < pos_j. After insertion:
    - c1 is at index pos_i in the 99-char text
    - Original CT[0:pos_i] is at indices 0:pos_i
    - Original CT[pos_i:pos_j] is at indices pos_i+1:pos_j+1
    - c2 is at index pos_j+1
    - Original CT[pos_j:] is at indices pos_j+2:
    """
    temp = ct_original[:pos_i] + c1 + ct_original[pos_i:]
    extended = list(temp[:pos_j + 1] + c2 + temp[pos_j + 1:])

    # Inserted CT positions in the 99-char text: pos_i and pos_j+1
    inserted_a = pos_i
    inserted_b = pos_j + 1

    rm_a = inv[inserted_a]
    rm_b = inv[inserted_b]

    if rm_a > rm_b:
        rm_a, rm_b = rm_b, rm_a

    score = 0
    for idx in range(N_CRIB):
        p97 = CRIB_POSITIONS_LIST[idx]
        if p97 < rm_a:
            pt99_pos = p97
        elif p97 < rm_b - 1:
            pt99_pos = p97 + 1
        else:
            pt99_pos = p97 + 2
        ct99_pos = perm[pt99_pos]
        if extended[ct99_pos] == CRIB_CHARS[idx]:
            score += 1
    return score


def get_pt97_nonconsec(ct_original, pos_i, pos_j, c1, c2, perm, inv):
    """Get 97-char plaintext for non-consecutive insertion."""
    temp = ct_original[:pos_i] + c1 + ct_original[pos_i:]
    extended = list(temp[:pos_j + 1] + c2 + temp[pos_j + 1:])
    inserted_a = pos_i
    inserted_b = pos_j + 1
    rm_a = inv[inserted_a]
    rm_b = inv[inserted_b]
    remove_set = {rm_a, rm_b}
    pt99 = [extended[perm[i]] for i in range(99)]
    pt97 = [pt99[i] for i in range(99) if i not in remove_set]
    return ''.join(pt97)


for c1, c2 in NC_LETTER_PAIRS:
    pair_label = c1 + c2
    pair_best = 0
    pair_best_config = None

    for pos_i, pos_j in nc_positions:
        for perm_idx in global_top_perm_indices:
            perm = ALL_PERMS[perm_idx]
            inv = ALL_INV[perm_idx]
            sc = score_nonconsec_fast(CT, pos_i, pos_j, c1, c2, perm, inv)
            checked_p3 += 1

            if sc > pair_best:
                pair_best = sc
                order_list = list(list(itertools.permutations(range(9)))[perm_idx])
                pair_best_config = {
                    'pos_i': pos_i, 'pos_j': pos_j,
                    'order': order_list,
                    'pt_preview': get_pt97_nonconsec(
                        CT, pos_i, pos_j, c1, c2, perm, inv)[:80],
                }

            if sc > phase3_global_best:
                phase3_global_best = sc

    phase3_results[pair_label] = {
        'best_score': pair_best,
        'best_config': pair_best_config,
    }

    elapsed_p3 = time.time() - t3_start
    rate_p3 = checked_p3 / elapsed_p3 if elapsed_p3 > 0 else 0
    remaining_p3 = (total_p3 - checked_p3) / rate_p3 if rate_p3 > 0 else 0
    print(f"  {pair_label}: best={pair_best}/24, "
          f"[{checked_p3:,}/{total_p3:,}, {rate_p3:.0f}/s, ETA {remaining_p3:.0f}s]")
    if pair_best_config:
        print(f"    best config: pos=({pair_best_config['pos_i']},{pair_best_config['pos_j']}), "
              f"order={pair_best_config['order']}")

results['phases']['phase3'] = {
    'description': 'Non-consecutive insertion in range 55-70, 6 letter pairs x top 1000 orderings',
    'total_checks': checked_p3,
    'time_seconds': time.time() - t3_start,
    'pair_results': {k: {'best_score': v['best_score'],
                         'best_config': v['best_config']} for k, v in phase3_results.items()},
    'global_best': phase3_global_best,
}

phase3_time = time.time() - t3_start
print(f"\n  Phase 3 complete: {checked_p3:,} checks in {phase3_time:.1f}s")

# =====================================================================
# FINAL SUMMARY
# =====================================================================
total_time = time.time() - t0
total_all_checks = total_checks + checked_p2 + checked_p3

global_best_all = max(
    max(v['best_score'] for v in phase1_results.values()),
    max(v['best_score'] for v in phase2_results.values()) if phase2_results else 0,
    phase3_global_best,
)

print("\n" + "=" * 70)
print("FINAL SUMMARY")
print("=" * 70)
print(f"Total checks:  {total_all_checks:,}")
print(f"Total time:    {total_time:.1f}s")
print(f"Global best:   {global_best_all}/24")

if global_best_all <= 6:
    classification = "NOISE"
elif global_best_all <= 9:
    classification = "NOISE (marginal)"
elif global_best_all <= 17:
    classification = "STORE"
else:
    classification = "SIGNAL"

print(f"Classification: {classification}")

# Phase 1 landscape summary
print("\nPhase 1 -- Score Landscape (CC insertion, all orderings):")
print("  Pos  Best  Mean")
for pos in sorted(phase1_results.keys()):
    info = phase1_results[pos]
    bar = "#" * info['best_score']
    marker = " <--" if pos in top3_positions else ""
    print(f"  {pos:3d}  {info['best_score']:4d}  {info['mean_score']:5.2f}  {bar}{marker}")

# Phase 2 summary
print("\nPhase 2 -- Best letter pairs per position:")
for pos in top3_positions:
    info = phase2_results[pos]
    print(f"  pos={pos}: best {info['best_pair']}={info['best_score']}/24")
    for pair, sc in info['top10_pairs'][:5]:
        print(f"    {pair}: {sc}/24")

# Phase 3 summary
print("\nPhase 3 -- Non-consecutive insertion:")
for pair, info in sorted(phase3_results.items(), key=lambda x: -x[1]['best_score']):
    cfg = info['best_config']
    if cfg:
        print(f"  {pair}: best={info['best_score']}/24 at ({cfg['pos_i']},{cfg['pos_j']})")

# Key analysis: is the region around 61-63 genuinely special?
p1_scores_by_pos = [(pos, info['best_score'], info['mean_score'])
                    for pos, info in phase1_results.items()]
p1_scores_by_pos.sort(key=lambda x: x[0])

region_61_63_best = [sc for pos, sc, _ in p1_scores_by_pos if 61 <= pos <= 63]
other_best = [sc for pos, sc, _ in p1_scores_by_pos if pos < 61 or pos > 63]
region_61_63_mean = [m for pos, _, m in p1_scores_by_pos if 61 <= pos <= 63]
other_mean = [m for pos, _, m in p1_scores_by_pos if pos < 61 or pos > 63]

avg_best_61_63 = sum(region_61_63_best) / len(region_61_63_best) if region_61_63_best else 0
avg_best_other = sum(other_best) / len(other_best) if other_best else 0
avg_mean_61_63 = sum(region_61_63_mean) / len(region_61_63_mean) if region_61_63_mean else 0
avg_mean_other = sum(other_mean) / len(other_mean) if other_mean else 0

print(f"\nRegion analysis (positions 61-63 vs rest):")
print(f"  Avg best score 61-63: {avg_best_61_63:.2f}")
print(f"  Avg best score other: {avg_best_other:.2f}")
print(f"  Avg mean score 61-63: {avg_mean_61_63:.2f}")
print(f"  Avg mean score other: {avg_mean_other:.2f}")
if avg_best_61_63 > avg_best_other + 1:
    print(f"  --> Region 61-63 IS elevated by {avg_best_61_63 - avg_best_other:.2f} (best)")
elif avg_mean_61_63 > avg_mean_other + 0.3:
    print(f"  --> Region 61-63 has higher mean by {avg_mean_61_63 - avg_mean_other:.2f}")
else:
    print(f"  --> Region 61-63 is NOT meaningfully elevated")

results['summary'] = {
    'total_checks': total_all_checks,
    'total_time_seconds': total_time,
    'global_best': global_best_all,
    'classification': classification,
    'region_analysis': {
        'avg_best_61_63': avg_best_61_63,
        'avg_best_other': avg_best_other,
        'avg_mean_61_63': avg_mean_61_63,
        'avg_mean_other': avg_mean_other,
    }
}

print("=" * 70)

os.makedirs('results', exist_ok=True)
outpath = 'results/e_chart_09_boundary.json'
with open(outpath, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"Artifact: {outpath}")
