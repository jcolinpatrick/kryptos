#!/usr/bin/env python3
"""
Reverse palette specificity analysis for the Beaufort A=0 keystream.

Given the 24 Beaufort A=0 keystream values at crib positions, enumerate
all C(26,7) = 657,800 seven-letter subsets and count how many keystream
values each subset captures.  Report the exact rank, percentile, and
distributional context for {B,G,I,K,O,W,Z}.

# METADATA
# id: e_palette_reverse_specificity_01
# family: statistical
# status: active
# has_results: Y
# registered: N
# best_score: n/a
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os, json, time
from itertools import combinations
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import BEAUFORT_KEYSTREAM_AT_CRIBS

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PALETTE = frozenset("BGIKOWZ")
KEYSTREAM = BEAUFORT_KEYSTREAM_AT_CRIBS  # 24 chars

assert len(KEYSTREAM) == 24
assert len(PALETTE) == 7
assert PALETTE <= set(ALPH)

# ── KA Polybius grid for structural analysis ──────────────────────────────
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_COLS = {}  # letter -> column index (5x6 grid, 6 cols)
for i, ch in enumerate(KA):
    KA_COLS[ch] = i % 6  # 5 rows x 6 cols (last row has 1 letter)

def main():
    t0 = time.time()

    # Count how many of the 24 keystream values are in each letter
    ks_counter = Counter(KEYSTREAM)
    print(f"Keystream: {KEYSTREAM}")
    print(f"Keystream letter frequencies: {dict(sorted(ks_counter.items()))}")
    print(f"Distinct keystream letters: {sorted(set(KEYSTREAM))}")
    print(f"Palette under test: {sorted(PALETTE)}")
    print()

    # Observed hit count for BGIKOWZ
    observed_hits = sum(1 for ch in KEYSTREAM if ch in PALETTE)
    print(f"Observed hits for BGIKOWZ: {observed_hits}/24")
    print()

    # Enumerate all C(26,7) subsets
    letters = list(ALPH)
    all_counts = []  # (hit_count, subset_tuple)

    # Precompute: for each subset, count = sum of ks_counter[ch] for ch in subset
    # This avoids scanning all 24 positions per subset
    ks_counts_by_letter = [ks_counter.get(ch, 0) for ch in ALPH]

    hit_distribution = Counter()  # hit_count -> number of subsets with that count

    n_better_or_equal = 0
    best_hits = 0
    best_subsets = []

    for combo in combinations(range(26), 7):
        hits = sum(ks_counts_by_letter[i] for i in combo)
        hit_distribution[hits] += 1

        if hits > best_hits:
            best_hits = hits
            best_subsets = [combo]
        elif hits == best_hits:
            best_subsets.append(combo)

        if hits >= observed_hits:
            n_better_or_equal += 1

    total_subsets = sum(hit_distribution.values())
    assert total_subsets == 657800, f"Expected 657800, got {total_subsets}"

    elapsed = time.time() - t0

    # ── Results ───────────────────────────────────────────────────────────
    print("=" * 70)
    print("RESULTS: Reverse Palette Specificity Analysis")
    print("=" * 70)

    print(f"\n## Method")
    print(f"Enumerated all C(26,7) = {total_subsets:,} seven-letter subsets.")
    print(f"For each, counted how many of the 24 Beaufort A=0 keystream values")
    print(f"(at crib positions) fall inside the subset.")
    print(f"Keystream: {KEYSTREAM}")
    print(f"Runtime: {elapsed:.1f}s")

    print(f"\n## Exact result for BGIKOWZ")
    print(f"Hit count: {observed_hits}/24")
    print(f"Subsets with >= {observed_hits} hits: {n_better_or_equal:,}")
    print(f"Rank: {n_better_or_equal} / {total_subsets:,}")
    pct = (1 - n_better_or_equal / total_subsets) * 100
    print(f"Percentile: {pct:.4f}%")
    p_value = n_better_or_equal / total_subsets
    print(f"p-value (fraction >= observed): {p_value:.6f} ({p_value:.4e})")

    for threshold_name, threshold in [("10%", 0.10), ("5%", 0.05), ("1%", 0.01), ("0.1%", 0.001), ("0.01%", 0.0001)]:
        in_top = p_value <= threshold
        print(f"  In top {threshold_name}? {'YES' if in_top else 'NO'}")

    print(f"\n## Distribution summary")
    print(f"{'Hits':>4}  {'Count':>8}  {'Cumul%':>8}  {'Bar'}")
    print(f"{'----':>4}  {'--------':>8}  {'--------':>8}  {'---'}")
    cumul = 0
    for hits in sorted(hit_distribution.keys(), reverse=True):
        count = hit_distribution[hits]
        cumul += count
        cumul_pct = cumul / total_subsets * 100
        bar = "#" * max(1, count * 60 // max(hit_distribution.values()))
        marker = "  <-- BGIKOWZ" if hits == observed_hits else ""
        print(f"{hits:>4}  {count:>8,}  {cumul_pct:>7.3f}%  {bar}{marker}")

    # Expected value under uniform: 24 * 7/26
    expected = 24 * 7 / 26
    print(f"\nExpected hits (uniform): {expected:.2f}")

    # Mean and std of the distribution
    total_hits_sum = sum(h * c for h, c in hit_distribution.items())
    mean_hits = total_hits_sum / total_subsets
    var_hits = sum((h - mean_hits)**2 * c for h, c in hit_distribution.items()) / total_subsets
    std_hits = var_hits ** 0.5
    print(f"Empirical mean: {mean_hits:.4f}")
    print(f"Empirical std:  {std_hits:.4f}")
    print(f"BGIKOWZ z-score: {(observed_hits - mean_hits) / std_hits:.2f}")

    print(f"\n## Best-performing comparison subsets")
    print(f"Maximum hits achieved: {best_hits}/24")
    print(f"Number of subsets achieving {best_hits}: {len(best_subsets)}")
    print()

    # Show top subsets with structural analysis
    # Convert indices back to letters and analyze
    shown = 0
    for combo in best_subsets[:20]:
        subset_letters = frozenset(ALPH[i] for i in combo)
        subset_str = "".join(sorted(subset_letters))

        # KA column analysis
        cols = [KA_COLS[ch] for ch in subset_letters]
        col_counter = Counter(cols)
        col_desc = ", ".join(f"col{c}:{n}" for c, n in sorted(col_counter.items()))

        # Arithmetic progression check
        indices = sorted(combo)
        diffs = [indices[i+1] - indices[i] for i in range(len(indices)-1)]
        is_ap = len(set(diffs)) == 1

        is_palette = subset_letters == PALETTE
        marker = " *** BGIKOWZ ***" if is_palette else ""
        print(f"  {subset_str}  hits={best_hits}  KA_cols=[{col_desc}]  AP={is_ap}{marker}")
        shown += 1

    if len(best_subsets) > 20:
        print(f"  ... and {len(best_subsets) - 20} more")

    # Also show where BGIKOWZ sits if not in best
    if observed_hits < best_hits:
        palette_cols = [KA_COLS[ch] for ch in PALETTE]
        pal_col_counter = Counter(palette_cols)
        pal_col_desc = ", ".join(f"col{c}:{n}" for c, n in sorted(pal_col_counter.items()))
        print(f"\n  BGIKOWZ (for comparison): hits={observed_hits}  KA_cols=[{pal_col_desc}]")

    # Analyze structural properties of best subsets
    print(f"\n  Structural analysis of top-{best_hits} subsets:")
    all_col_distributions = []
    for combo in best_subsets:
        subset_letters = [ALPH[i] for i in combo]
        cols = tuple(sorted(KA_COLS[ch] for ch in subset_letters))
        all_col_distributions.append(cols)
    col_dist_counter = Counter(all_col_distributions)
    print(f"  Distinct KA column distributions: {len(col_dist_counter)}")
    for dist, cnt in col_dist_counter.most_common(5):
        print(f"    {dist}: {cnt} subsets")

    # Check if BGIKOWZ columns are special
    palette_cols_sorted = tuple(sorted(KA_COLS[ch] for ch in PALETTE))
    print(f"\n  BGIKOWZ KA columns: {palette_cols_sorted}")
    unique_palette_cols = set(palette_cols_sorted)
    print(f"  BGIKOWZ uses {len(unique_palette_cols)} distinct KA columns: {sorted(unique_palette_cols)}")

    print(f"\n## Interpretation")
    if p_value <= 0.01:
        print(f"The palette BGIKOWZ captures {observed_hits}/24 keystream values.")
        print(f"Only {n_better_or_equal:,} of {total_subsets:,} subsets ({p_value:.4e}) do as well or better.")
        print(f"This is in the top {p_value*100:.2f}% — a statistically notable concentration.")
        print(f"However, this is a SINGLE test on the SAME data that generated the hypothesis.")
        print(f"The palette was SELECTED because it appeared at null positions; testing it")
        print(f"against the keystream is a secondary observation, not an independent confirmation.")
    elif p_value <= 0.05:
        print(f"Marginal: p={p_value:.4f}. Suggestive but not strong evidence.")
        print(f"Would not survive multiple-testing correction across the analysis pipeline.")
    else:
        print(f"Not significant: p={p_value:.4f}. BGIKOWZ is unremarkable among 7-letter subsets")
        print(f"for keystream overlap. The palette's interest comes from null positions, not keystream.")

    print(f"\n## What this means for the null-palette hypothesis")
    if p_value <= 0.01:
        print(f"UPGRADED: The palette is not just concentrated at null positions — it also")
        print(f"captures an unusual fraction of the keystream. This is consistent with a")
        print(f"generative mechanism linking nulls and keystream (e.g., both derived from")
        print(f"the same Polybius/KA structure). But note: the palette was hypothesis-selected,")
        print(f"so the effective search space is larger than this single test implies.")
    elif p_value <= 0.05:
        print(f"TENTATIVE: Weak evidence of keystream-palette coupling. Not strong enough to")
        print(f"change research priorities, but worth noting as a secondary signal.")
    else:
        print(f"NEUTRAL: The keystream overlap is unremarkable. The palette's significance")
        print(f"rests entirely on its concentration at null positions, not on keystream coupling.")
        print(f"The null-palette hypothesis is neither upgraded nor downgraded by this test.")

    print(f"\n## Recommended next action")
    if p_value <= 0.05:
        print(f"1. Test whether the result holds under Vigenère and Variant Beaufort keystreams")
        print(f"2. Run a permutation test: shuffle null positions, re-derive palette, re-test")
        print(f"3. Check if the top-performing subsets share the same KA column structure as BGIKOWZ")
    else:
        print(f"1. Do NOT further invest in keystream-palette coupling as a research direction")
        print(f"2. The palette's value is at the stego layer (null positions), not the cipher layer")
        print(f"3. Focus palette research on placement rules (mod-7, mod-5) not keystream overlap")

    # ── Save results ──────────────────────────────────────────────────────
    results = {
        "test": "reverse_palette_specificity",
        "keystream": KEYSTREAM,
        "palette": sorted(PALETTE),
        "observed_hits": observed_hits,
        "total_subsets": total_subsets,
        "n_better_or_equal": n_better_or_equal,
        "p_value": p_value,
        "percentile": pct,
        "best_hits": best_hits,
        "n_best_subsets": len(best_subsets),
        "distribution": {str(k): v for k, v in sorted(hit_distribution.items())},
        "mean_hits": mean_hits,
        "std_hits": std_hits,
        "z_score": (observed_hits - mean_hits) / std_hits,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    out_path = os.path.join(_ROOT, "results", "palette_reverse_specificity_01.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
