#!/usr/bin/env python3
"""
Phase 2: Resolving the 7 Varying Null Positions (OQ-2)

The (pos%7, pos%5) table classifies 35 palette positions perfectly.
When applied to ALL 97 positions, 18 non-palette positions also fall in "null" cells.
Hypothesis VP-1: The 7 varying nulls are drawn from these false-positive positions.

After excluding crib-range positions, 15 candidates remain -> C(15,7)=6,435 masks.
Note: all masks score identically at crib positions (24/24) because nulls never
overlap cribs (S6). The value of this phase is the VP-1 overlap test and second
palette analysis, not crib-score discrimination.

Output: results/varying_null_resolution.json
"""
import sys, os, json
from collections import defaultdict
from itertools import combinations
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, CRIB_DICT, ALPH, ALPH_IDX, MOD,
    BEAUFORT_KEYSTREAM_AT_CRIBS,
)

# ── Build the 7×5 classification table ───────────────────────────────────
PALETTE_POSITIONS = sorted(p for p in range(CT_LEN) if CT[p] in NULL_PALETTE)

cell_labels = {}  # (r,c) -> 'N', 'R', 'M', or None
cell_positions = defaultdict(list)
for p in PALETTE_POSITIONS:
    cell_positions[(p % 7, p % 5)].append(p)

for r in range(7):
    for c in range(5):
        positions = cell_positions.get((r, c), [])
        if not positions:
            cell_labels[(r, c)] = None
        else:
            null_count = sum(1 for p in positions if p in CONSENSUS_NULL_POSITIONS)
            real_count = len(positions) - null_count
            if null_count > 0 and real_count == 0:
                cell_labels[(r, c)] = 'N'
            elif real_count > 0 and null_count == 0:
                cell_labels[(r, c)] = 'R'
            else:
                cell_labels[(r, c)] = 'M'

NULL_CELLS = {(r, c) for (r, c), v in cell_labels.items() if v in ('N', 'M')}

# ── Find false-positive positions ────────────────────────────────────────
# Non-palette positions that fall in null/mixed cells
false_positive_positions = sorted(
    p for p in range(CT_LEN)
    if CT[p] not in NULL_PALETTE
    and (p % 7, p % 5) in NULL_CELLS
)

# Exclude crib-range positions
crib_range = set()
for start, word in [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]:
    for i in range(len(word)):
        crib_range.add(start + i)

fp_no_cribs = sorted(p for p in false_positive_positions if p not in crib_range)

# Known varying null ranges from memory
KNOWN_VARYING_RANGES = [{38,39,40,41,42,43,44,45}, {54,55,56}, {87,88}, {93,94,95,96}]
known_varying_union = set()
for r in KNOWN_VARYING_RANGES:
    known_varying_union |= r

results = {
    "experiment": "e_varying_null_resolution",
    "date": datetime.now(timezone.utc).isoformat(),
}


def score_mask(null_positions):
    """Score a 24-position null mask against cribs using Beaufort A=0.

    Returns crib score (0-24): how many crib positions have consistent keystream.
    A 'consistent' position means the Beaufort keystream value at that position
    matches the known keystream JLJODEGKUKKKLOCGGBGOKTRU.
    """
    ks_expected = [ALPH_IDX[c] for c in BEAUFORT_KEYSTREAM_AT_CRIBS]
    crib_pos_sorted = sorted(CRIB_POSITIONS)

    score = 0
    for i, cp in enumerate(crib_pos_sorted):
        if cp in null_positions:
            continue  # null at crib position = invalid, but shouldn't happen per S6
        ct_val = ALPH_IDX[CT[cp]]
        pt_val = ALPH_IDX[CRIB_DICT[cp]]
        ks_val = (ct_val + pt_val) % MOD  # Beaufort: K = (C + P) mod 26
        if ks_val == ks_expected[i]:
            score += 1
    return score


if __name__ == "__main__":
    print("=" * 72)
    print("Phase 2: Varying Null Resolution (OQ-2)")
    print("=" * 72)

    # Step 1: Report false-positive positions
    print(f"\n16 non-palette positions in null cells: {false_positive_positions}")
    print(f"  After removing crib positions: {fp_no_cribs} ({len(fp_no_cribs)} positions)")

    # Step 2: Check overlap with known varying ranges
    overlap = sorted(p for p in fp_no_cribs if p in known_varying_union)
    print(f"\n  Overlap with known varying ranges: {overlap} ({len(overlap)}/{len(fp_no_cribs)})")

    results["false_positive_positions"] = false_positive_positions
    results["fp_after_crib_exclusion"] = fp_no_cribs
    results["overlap_with_varying_ranges"] = overlap
    results["overlap_count"] = len(overlap)

    # Step 3: VP-1 test — if >=6 overlap, hypothesis is supported
    vp1_supported = len(overlap) >= 6
    print(f"\n  VP-1 hypothesis (>=6/7 from false positives): {'SUPPORTED' if vp1_supported else 'FAILED'}")
    results["vp1_supported"] = vp1_supported

    if vp1_supported and len(fp_no_cribs) >= 7:
        # Step 4: Enumerate C(N,7) masks and score each
        n_candidates = len(fp_no_cribs)
        n_masks = 1
        for i in range(7):
            n_masks = n_masks * (n_candidates - i) // (i + 1)
        print(f"\n  Candidate pool: {n_candidates} positions -> C({n_candidates},7) = {n_masks} masks")

        best_score = 0
        best_masks = []
        score_distribution = defaultdict(int)

        for varying_7 in combinations(fp_no_cribs, 7):
            full_mask = CONSENSUS_NULL_POSITIONS | set(varying_7)
            # Verify: 24 nulls, no overlap with cribs
            if len(full_mask) != 24:
                continue
            if full_mask & CRIB_POSITIONS:
                continue

            score = score_mask(full_mask)
            score_distribution[score] += 1

            if score > best_score:
                best_score = score
                best_masks = [sorted(varying_7)]
            elif score == best_score:
                best_masks.append(sorted(varying_7))

        print(f"\n  Masks tested: {sum(score_distribution.values())}")
        print(f"  Best score: {best_score}/24")
        print(f"  Masks at best: {len(best_masks)}")
        print(f"  Score distribution: {dict(sorted(score_distribution.items()))}")

        results["masks_tested"] = sum(score_distribution.values())
        results["best_score"] = best_score
        results["best_masks_count"] = len(best_masks)
        results["best_masks_sample"] = best_masks[:20]  # first 20
        results["score_distribution"] = dict(sorted(score_distribution.items()))

        # The known keystream is FIXED — all masks should score 24/24 at crib positions
        # because nulls don't overlap cribs (S6). Score variation comes from the mask
        # not affecting crib positions at all. So we expect ALL masks to score 24/24.
        # The real discriminator is the cipher mechanism, not the crib score.
        # Let's also compute a different metric: how many of the 7 varying positions
        # have CT letters that fall in a restricted set (second palette test).
        print(f"\n  --- Second Palette Analysis (VM-1) ---")
        varying_letters_all = set()
        for combo in best_masks[:100]:
            for p in combo:
                varying_letters_all.add(CT[p])
        print(f"  Distinct letters at varying positions (across top masks): {sorted(varying_letters_all)}")
        print(f"  Count: {len(varying_letters_all)}/26")
        results["varying_letters_pool"] = sorted(varying_letters_all)
    else:
        print("\n  VP-1 not supported — skipping mask enumeration")
        results["masks_tested"] = 0

    # Write results
    out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'varying_null_resolution.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results: {out_path}")
