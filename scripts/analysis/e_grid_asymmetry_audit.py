#!/usr/bin/env python3
"""
Cipher: statistical_audit
Family: analysis
Status: active
Keyspace: ~50 grid widths × MC simulations
Last run: never
Best score: N/A (diagnostic, not attack)

Rigorous audit of the 7×14 grid palette asymmetry claim.

Six analyses:
  1. All viable grid widths (2-48): which show significant left/right asymmetry?
  2. Linear position bias: is palette clustering just early-in-string?
  3. Optimal grid width for palette separation (chi-square across columns)
  4. Interpretive implications (reported textually)
  5. Column-pair correlation matrix in 7×14 grid
  6. Row analysis in 7×14 grid

All p-values are two-tailed or one-tailed as noted. Pre-registered vs post-hoc
is stated explicitly.

Author: statistics-agent
"""

import sys, os, json, math
from collections import Counter
from itertools import combinations

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS

# ── Constants ──────────────────────────────────────────────────────────────
PALETTE = frozenset("BGIKOWZ")
PAL_POSITIONS = [i for i in range(CT_LEN) if CT[i] in PALETTE]
NONPAL_POSITIONS = [i for i in range(CT_LEN) if CT[i] not in PALETTE]
N_PAL = len(PAL_POSITIONS)  # 35
N_TOTAL = CT_LEN             # 97

# 17 consensus null positions from MEMORY.md
CONSENSUS_NULLS = frozenset([0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85])

import random
random.seed(20260320)

# ── Utility functions ──────────────────────────────────────────────────────

def is_palette(pos):
    return CT[pos] in PALETTE

def arrange_grid(width):
    """Arrange CT positions into rows of given width. Last row may be short."""
    rows = []
    for start in range(0, CT_LEN, width):
        rows.append(list(range(start, min(start + width, CT_LEN))))
    return rows

def left_right_counts(width):
    """Count palette letters in left half vs right half of grid with given width."""
    half = width // 2
    left_count = 0
    right_count = 0
    left_total = 0
    right_total = 0
    rows = arrange_grid(width)
    for row in rows:
        for col_idx, pos in enumerate(row):
            if col_idx < half:
                left_total += 1
                if is_palette(pos):
                    left_count += 1
            elif col_idx >= width - half:
                right_total += 1
                if is_palette(pos):
                    right_count += 1
            # If width is odd, middle column is excluded from both halves
    return left_count, left_total, right_count, right_total

def mc_pvalue_left_geq(observed_left, left_total, right_total, n_pal, n_total, n_mc=200000):
    """
    Monte Carlo p-value: P(left_palette >= observed_left) under random permutation.
    We shuffle palette membership across all positions, then count how many
    land in the left half.
    """
    count_geq = 0
    positions = list(range(n_total))
    # Only consider positions that are in left or right (exclude middle column positions)
    for _ in range(n_mc):
        random.shuffle(positions)
        pal_set = set(positions[:n_pal])
        left_pal = sum(1 for p in range(left_total) if p in pal_set)
        # This is wrong — we need to map to grid positions
        # Actually: just count how many of the first n_pal shuffled indices
        # fall in the left-half positions.
        # Simpler: we need the actual left-half position set
        pass
    # Let me redo this properly
    return -1  # placeholder

def mc_pvalue_left_geq_v2(observed_left, left_positions, right_positions, n_mc=200000):
    """
    Monte Carlo p-value: P(left_palette >= observed_left) under random permutation
    of palette labels across all CT positions.

    left_positions, right_positions: sets of CT position indices in left/right halves.
    We randomly assign N_PAL positions as "palette" and count how many fall in left_positions.
    """
    all_positions = list(range(N_TOTAL))
    left_set = set(left_positions)
    count_geq = 0
    for _ in range(n_mc):
        random.shuffle(all_positions)
        simulated_pal = set(all_positions[:N_PAL])
        sim_left = len(simulated_pal & left_set)
        if sim_left >= observed_left:
            count_geq += 1
    return count_geq / n_mc

def get_half_positions(width):
    """Get sets of CT positions in left half and right half of the grid."""
    half = width // 2
    left_pos = []
    right_pos = []
    rows = arrange_grid(width)
    for row in rows:
        for col_idx, pos in enumerate(row):
            if col_idx < half:
                left_pos.append(pos)
            elif col_idx >= width - half:
                right_pos.append(pos)
    return left_pos, right_pos

def hypergeometric_pvalue(k, K, n, N):
    """
    P(X >= k) where X ~ Hypergeometric(N, K, n).
    N = population size, K = success states in population,
    n = draws, k = observed successes.

    Uses exact computation with log-factorials.
    """
    def log_comb(a, b):
        if b < 0 or b > a:
            return float('-inf')
        return math.lgamma(a+1) - math.lgamma(b+1) - math.lgamma(a-b+1)

    pval = 0.0
    for x in range(k, min(K, n) + 1):
        log_p = log_comb(K, x) + log_comb(N-K, n-x) - log_comb(N, n)
        pval += math.exp(log_p)
    return min(pval, 1.0)

def chi_square_columns(width):
    """
    Chi-square statistic for palette vs non-palette across columns of the grid.
    Tests whether palette distribution is uniform across columns.
    Returns (chi2, df, column_counts, column_totals).
    """
    rows = arrange_grid(width)
    n_cols = width
    col_pal = [0] * n_cols
    col_total = [0] * n_cols

    for row in rows:
        for col_idx, pos in enumerate(row):
            col_total[col_idx] += 1
            if is_palette(pos):
                col_pal[col_idx] += 1

    # Expected palette count per column: col_total[c] * (N_PAL / N_TOTAL)
    overall_rate = N_PAL / N_TOTAL
    chi2 = 0.0
    for c in range(n_cols):
        if col_total[c] == 0:
            continue
        expected = col_total[c] * overall_rate
        if expected > 0:
            chi2 += (col_pal[c] - expected)**2 / expected
        expected_non = col_total[c] * (1 - overall_rate)
        if expected_non > 0:
            chi2 += ((col_total[c] - col_pal[c]) - expected_non)**2 / expected_non

    df = n_cols - 1  # columns with data
    return chi2, df, col_pal, col_total

def chi_square_pvalue_mc(observed_chi2, width, n_mc=100000):
    """
    Monte Carlo p-value for chi-square statistic: P(chi2 >= observed_chi2)
    under random assignment of palette membership.
    """
    rows = arrange_grid(width)
    n_cols = width

    # Pre-compute column assignments for each position
    pos_to_col = {}
    col_total = [0] * n_cols
    for row in rows:
        for col_idx, pos in enumerate(row):
            pos_to_col[pos] = col_idx
            col_total[col_idx] += 1

    all_positions = list(range(N_TOTAL))
    overall_rate = N_PAL / N_TOTAL
    count_geq = 0

    for _ in range(n_mc):
        random.shuffle(all_positions)
        sim_pal = set(all_positions[:N_PAL])

        col_pal = [0] * n_cols
        for p in sim_pal:
            if p in pos_to_col:
                col_pal[pos_to_col[p]] += 1

        chi2 = 0.0
        for c in range(n_cols):
            if col_total[c] == 0:
                continue
            expected = col_total[c] * overall_rate
            if expected > 0:
                chi2 += (col_pal[c] - expected)**2 / expected
            expected_non = col_total[c] * (1 - overall_rate)
            if expected_non > 0:
                chi2 += ((col_total[c] - col_pal[c]) - expected_non)**2 / expected_non

        if chi2 >= observed_chi2:
            count_geq += 1

    return count_geq / n_mc

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 1: All grid widths — left/right asymmetry
# ══════════════════════════════════════════════════════════════════════════

def analysis_1():
    print("=" * 80)
    print("ANALYSIS 1: Left/right palette asymmetry across all grid widths (2-48)")
    print("=" * 80)
    print()
    print("For each width w, we arrange 97 chars in rows of w, split into")
    print("left w//2 columns and right w//2 columns (odd widths: middle excluded).")
    print("P-value: P(left_palette >= observed) under random palette assignment.")
    print("This is a ONE-SIDED test (testing for LEFT enrichment specifically).")
    print()
    print("PRE-REGISTERED TEST: width=14 (the claimed finding).")
    print("ALL OTHER WIDTHS: post-hoc scan (requires Bonferroni correction).")
    print()

    results = []

    for w in range(2, 49):
        left_pos, right_pos = get_half_positions(w)
        left_pal = sum(1 for p in left_pos if is_palette(p))
        right_pal = sum(1 for p in right_pos if is_palette(p))
        left_total = len(left_pos)
        right_total = len(right_pos)

        if left_total == 0 or right_total == 0:
            continue

        left_rate = left_pal / left_total if left_total > 0 else 0
        right_rate = right_pal / right_total if right_total > 0 else 0

        # Exact hypergeometric p-value: P(X >= left_pal) where X is the number
        # of palette letters landing in the left half by chance.
        # Population N=97, K=35 palette, n=left_total draws
        pval = hypergeometric_pvalue(left_pal, N_PAL, left_total, N_TOTAL)

        results.append({
            'width': w,
            'n_rows': math.ceil(CT_LEN / w),
            'left_pal': left_pal,
            'left_total': left_total,
            'left_rate': left_rate,
            'right_pal': right_pal,
            'right_total': right_total,
            'right_rate': right_rate,
            'pval_hyper': pval,
        })

    # Sort by p-value
    results_sorted = sorted(results, key=lambda x: x['pval_hyper'])

    print(f"{'Width':>5} {'Rows':>4} {'Left':>10} {'Right':>10} {'L_rate':>7} {'R_rate':>7} {'p-value':>12} {'Sig?':>6}")
    print("-" * 75)
    for r in results:
        sig = "***" if r['pval_hyper'] < 0.001 else ("**" if r['pval_hyper'] < 0.01 else ("*" if r['pval_hyper'] < 0.05 else ""))
        marker = " <-- CLAIMED" if r['width'] == 14 else ""
        print(f"{r['width']:>5} {r['n_rows']:>4} {r['left_pal']:>4}/{r['left_total']:<4} {r['right_pal']:>4}/{r['right_total']:<4} "
              f"{r['left_rate']:>7.1%} {r['right_rate']:>7.1%} {r['pval_hyper']:>12.6f} {sig:>6}{marker}")

    print()
    print("Top 10 by p-value:")
    print(f"{'Rank':>4} {'Width':>5} {'Rows':>4} {'Left':>10} {'Right':>10} {'L_rate':>7} {'R_rate':>7} {'p-value':>12}")
    print("-" * 75)
    for rank, r in enumerate(results_sorted[:10], 1):
        marker = " <-- CLAIMED" if r['width'] == 14 else ""
        print(f"{rank:>4} {r['width']:>5} {r['n_rows']:>4} {r['left_pal']:>4}/{r['left_total']:<4} {r['right_pal']:>4}/{r['right_total']:<4} "
              f"{r['left_rate']:>7.1%} {r['right_rate']:>7.1%} {r['pval_hyper']:>12.6f}{marker}")

    # Bonferroni threshold for 47 tests
    n_tests = len(results)
    bonf_thresh = 0.01 / n_tests
    sig_after_bonf = [r for r in results if r['pval_hyper'] < bonf_thresh]

    print()
    print(f"Bonferroni correction for {n_tests} tests: threshold = {bonf_thresh:.6f}")
    print(f"Widths surviving Bonferroni at alpha=0.01: {[r['width'] for r in sig_after_bonf] if sig_after_bonf else 'NONE'}")

    # MC validation for width=14
    print()
    print("Monte Carlo validation for width=14 (200K shuffles)...")
    left_pos_14, right_pos_14 = get_half_positions(14)
    left_pal_14 = sum(1 for p in left_pos_14 if is_palette(p))
    mc_pval_14 = mc_pvalue_left_geq_v2(left_pal_14, left_pos_14, right_pos_14, n_mc=200000)
    print(f"  Hypergeometric p-value: {[r for r in results if r['width']==14][0]['pval_hyper']:.6f}")
    print(f"  Monte Carlo p-value:    {mc_pval_14:.6f}")

    return results

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 2: Linear position bias
# ══════════════════════════════════════════════════════════════════════════

def analysis_2():
    print()
    print("=" * 80)
    print("ANALYSIS 2: Linear position bias — are palette letters early in CT?")
    print("=" * 80)
    print()

    pal_mean = sum(PAL_POSITIONS) / N_PAL
    nonpal_mean = sum(NONPAL_POSITIONS) / len(NONPAL_POSITIONS)
    overall_mean = sum(range(CT_LEN)) / CT_LEN  # = 48.0

    print(f"Mean position of palette letters:     {pal_mean:.2f}")
    print(f"Mean position of non-palette letters:  {nonpal_mean:.2f}")
    print(f"Overall mean position:                 {overall_mean:.2f}")
    print(f"Palette shift from overall:            {pal_mean - overall_mean:+.2f}")
    print()

    # Permutation test: P(mean_pal <= observed) under random assignment
    n_mc = 200000
    all_positions = list(range(CT_LEN))
    count_leq = 0
    for _ in range(n_mc):
        random.shuffle(all_positions)
        sim_mean = sum(all_positions[:N_PAL]) / N_PAL
        if sim_mean <= pal_mean:
            count_leq += 1

    pval_early = count_leq / n_mc
    print(f"Permutation test P(mean_pal <= {pal_mean:.2f}): {pval_early:.6f} ({n_mc} shuffles)")
    print(f"  (Tests whether palette letters are significantly EARLIER in the string)")
    print()

    # Quartile analysis
    q1 = [p for p in PAL_POSITIONS if p < 24]
    q2 = [p for p in PAL_POSITIONS if 24 <= p < 48]
    q3 = [p for p in PAL_POSITIONS if 48 <= p < 73]
    q4 = [p for p in PAL_POSITIONS if 73 <= p]

    print("Palette distribution by quartile of CT:")
    print(f"  Positions  0-23: {len(q1):>2} palette / 24 total = {len(q1)/24:.1%}")
    print(f"  Positions 24-47: {len(q2):>2} palette / 24 total = {len(q2)/24:.1%}")
    print(f"  Positions 48-72: {len(q3):>2} palette / 25 total = {len(q3)/25:.1%}")
    print(f"  Positions 73-96: {len(q4):>2} palette / 24 total = {len(q4)/24:.1%}")
    print()

    # Running average
    print("Palette density in sliding window of 14 positions:")
    for start in range(0, CT_LEN - 13, 14):
        end = min(start + 14, CT_LEN)
        window = range(start, end)
        pal_in_window = sum(1 for p in window if is_palette(p))
        print(f"  Positions {start:>2}-{end-1:<2}: {pal_in_window:>2}/{end-start} = {pal_in_window/(end-start):.1%}")

    # Correlation between position and palette membership
    # Point-biserial correlation
    pal_indicator = [1 if CT[i] in PALETTE else 0 for i in range(CT_LEN)]
    pos_vals = list(range(CT_LEN))

    mean_x = sum(pos_vals) / CT_LEN
    mean_y = sum(pal_indicator) / CT_LEN

    cov_xy = sum((pos_vals[i] - mean_x) * (pal_indicator[i] - mean_y) for i in range(CT_LEN)) / CT_LEN
    var_x = sum((p - mean_x)**2 for p in pos_vals) / CT_LEN
    var_y = sum((y - mean_y)**2 for y in pal_indicator) / CT_LEN

    r_pb = cov_xy / (var_x * var_y)**0.5 if var_x > 0 and var_y > 0 else 0

    print()
    print(f"Point-biserial correlation (position vs palette membership): r = {r_pb:.4f}")
    if abs(r_pb) < 0.1:
        print("  -> WEAK correlation. Linear position is NOT a strong driver.")
    elif abs(r_pb) < 0.3:
        print("  -> MODERATE correlation. Linear position contributes but doesn't fully explain.")
    else:
        print("  -> STRONG correlation. Linear position dominates the effect.")

    # Critical test: if we REMOVE the linear trend, does width=14 remain significant?
    # Approach: residualize palette membership on position, then test grid asymmetry.
    # Simpler: condition on position quintiles and test within-quintile asymmetry.
    print()
    print("CONDITIONAL TEST: Does width=14 asymmetry survive after controlling for position?")
    print("Method: stratified permutation test. Divide CT into 7 segments of ~14 chars.")
    print("Permute palette labels WITHIN each segment, then measure grid asymmetry.")

    rows_14 = arrange_grid(14)
    # Each row of the 7x14 grid is one segment
    left_pos_14, right_pos_14 = get_half_positions(14)
    left_set_14 = set(left_pos_14)
    observed_left_14 = sum(1 for p in left_set_14 if is_palette(p))

    n_mc_cond = 200000
    count_geq = 0

    for _ in range(n_mc_cond):
        # Within each row, shuffle palette membership
        simulated_pal = set()
        for row in rows_14:
            pal_in_row = [p for p in row if is_palette(p)]
            n_pal_row = len(pal_in_row)
            # Randomly assign n_pal_row positions in this row as "palette"
            shuffled_row = list(row)
            random.shuffle(shuffled_row)
            simulated_pal.update(shuffled_row[:n_pal_row])

        sim_left = len(simulated_pal & left_set_14)
        if sim_left >= observed_left_14:
            count_geq += 1

    pval_conditional = count_geq / n_mc_cond
    print(f"  Observed left palette (width=14): {observed_left_14}")
    print(f"  Stratified permutation p-value:   {pval_conditional:.6f} ({n_mc_cond} shuffles)")
    print(f"  (Permutes palette within each ROW of the 7x14 grid,")
    print(f"   eliminating the effect of which rows are palette-heavy)")
    print()

    if pval_conditional < 0.01:
        print("  -> SIGNIFICANT after controlling for row (= position segment).")
        print("     The asymmetry is NOT just a linear position artifact.")
    else:
        print("  -> NOT SIGNIFICANT after controlling for row.")
        print("     The asymmetry is largely explained by which ROWS have more palette.")
        print("     Grid structure adds nothing beyond the linear position effect.")

    return {
        'pal_mean': pal_mean,
        'nonpal_mean': nonpal_mean,
        'pval_early': pval_early,
        'r_pointbiserial': r_pb,
        'pval_conditional_width14': pval_conditional,
    }

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 3: Optimal grid width (chi-square separation)
# ══════════════════════════════════════════════════════════════════════════

def analysis_3():
    print()
    print("=" * 80)
    print("ANALYSIS 3: Optimal grid width for palette column-separation (chi-square)")
    print("=" * 80)
    print()
    print("For each width w, compute chi-square statistic for palette vs non-palette")
    print("distribution across the w columns. Higher chi-square = stronger separation.")
    print("MC p-value computed for top candidates.")
    print()

    results = []
    for w in range(2, 49):
        chi2, df, col_pal, col_total = chi_square_columns(w)
        results.append({
            'width': w,
            'chi2': chi2,
            'df': df,
            'col_pal': col_pal,
            'col_total': col_total,
        })

    results_sorted = sorted(results, key=lambda x: x['chi2'], reverse=True)

    print(f"{'Rank':>4} {'Width':>5} {'df':>3} {'Chi2':>10} {'Chi2/df':>8}")
    print("-" * 40)
    for rank, r in enumerate(results_sorted[:20], 1):
        marker = " <-- CLAIMED" if r['width'] == 14 else ""
        print(f"{rank:>4} {r['width']:>5} {r['df']:>3} {r['chi2']:>10.2f} {r['chi2']/r['df'] if r['df']>0 else 0:>8.2f}{marker}")

    # MC p-values for top 5
    print()
    print("Monte Carlo p-values for top 5 widths (100K shuffles each):")
    for r in results_sorted[:5]:
        mc_pval = chi_square_pvalue_mc(r['chi2'], r['width'], n_mc=100000)
        marker = " <-- CLAIMED" if r['width'] == 14 else ""
        print(f"  Width {r['width']:>2}: chi2={r['chi2']:.2f}, MC p={mc_pval:.6f}{marker}")

    # Also compute for width=14 specifically if not in top 5
    w14_result = [r for r in results if r['width'] == 14][0]
    if w14_result not in results_sorted[:5]:
        mc_pval_14 = chi_square_pvalue_mc(w14_result['chi2'], 14, n_mc=100000)
        print(f"  Width 14: chi2={w14_result['chi2']:.2f}, MC p={mc_pval_14:.6f} <-- CLAIMED")

    # Detail for width=14
    print()
    print("Width=14 column detail:")
    w14 = w14_result
    overall_rate = N_PAL / N_TOTAL
    print(f"{'Col':>4} {'Pal':>4} {'Total':>5} {'Rate':>7} {'Expected':>8} {'(O-E)^2/E':>10}")
    for c in range(14):
        expected = w14['col_total'][c] * overall_rate
        contrib = (w14['col_pal'][c] - expected)**2 / expected if expected > 0 else 0
        print(f"{c:>4} {w14['col_pal'][c]:>4} {w14['col_total'][c]:>5} {w14['col_pal'][c]/w14['col_total'][c]:.1%}   {expected:>8.2f} {contrib:>10.3f}")

    return results_sorted

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 5: Column-pair correlations in 7×14 grid
# ══════════════════════════════════════════════════════════════════════════

def analysis_5():
    print()
    print("=" * 80)
    print("ANALYSIS 5: Column-pair palette correlations in 7x14 grid")
    print("=" * 80)
    print()

    rows = arrange_grid(14)
    n_rows = len(rows)  # 7

    # Build palette indicator per (row, col)
    grid_pal = []
    for row in rows:
        row_pal = []
        for pos in row:
            row_pal.append(1 if is_palette(pos) else 0)
        # Pad short rows
        while len(row_pal) < 14:
            row_pal.append(None)
        grid_pal.append(row_pal)

    print("Palette map (7x14 grid, 1=palette, 0=non-palette, .=empty):")
    print(f"{'':>6}", end="")
    for c in range(14):
        print(f"{c:>3}", end="")
    print()
    for r_idx, row in enumerate(grid_pal):
        print(f"Row {r_idx}: ", end="")
        for val in row:
            if val is None:
                print("  .", end="")
            else:
                print(f"  {val}", end="")
        # Also show the actual letters
        print("   |  ", end="")
        for pos_idx, pos in enumerate(rows[r_idx]):
            marker = "*" if is_palette(pos) else " "
            print(f"{CT[pos]}{marker}", end="")
        print()

    print()

    # Phi coefficient (correlation for binary variables) between column pairs
    # Only use rows where both columns have data
    print("Column-pair phi coefficients (correlation of palette presence across rows):")
    print()

    phi_matrix = [[None]*14 for _ in range(14)]

    for c1 in range(14):
        for c2 in range(c1, 14):
            # Get paired observations
            pairs = []
            for r_idx in range(n_rows):
                v1 = grid_pal[r_idx][c1]
                v2 = grid_pal[r_idx][c2]
                if v1 is not None and v2 is not None:
                    pairs.append((v1, v2))

            if len(pairs) < 3:
                phi_matrix[c1][c2] = None
                phi_matrix[c2][c1] = None
                continue

            # 2x2 contingency table
            a = sum(1 for x, y in pairs if x == 1 and y == 1)
            b = sum(1 for x, y in pairs if x == 1 and y == 0)
            c = sum(1 for x, y in pairs if x == 0 and y == 1)
            d = sum(1 for x, y in pairs if x == 0 and y == 0)

            denom = ((a+b)*(c+d)*(a+c)*(b+d))**0.5
            if denom == 0:
                phi = 0
            else:
                phi = (a*d - b*c) / denom

            phi_matrix[c1][c2] = phi
            phi_matrix[c2][c1] = phi

    # Print matrix
    print(f"{'':>6}", end="")
    for c in range(14):
        print(f"  c{c:<2}", end="")
    print()
    for c1 in range(14):
        print(f" c{c1:<2}  ", end="")
        for c2 in range(14):
            if phi_matrix[c1][c2] is None:
                print("    .", end="")
            elif c1 == c2:
                print("  1.0", end="")
            else:
                print(f" {phi_matrix[c1][c2]:>4.2f}", end="")
        print()

    # Find strongest correlations
    print()
    print("Strongest positive column-pair correlations (same rows both palette):")
    pairs_list = []
    for c1 in range(14):
        for c2 in range(c1+1, 14):
            if phi_matrix[c1][c2] is not None:
                pairs_list.append((phi_matrix[c1][c2], c1, c2))

    pairs_list.sort(reverse=True)
    for phi, c1, c2 in pairs_list[:10]:
        print(f"  Columns ({c1:>2},{c2:>2}): phi = {phi:>6.3f}")

    print()
    print("Strongest negative correlations (palette in one -> non-palette in other):")
    pairs_list.sort()
    for phi, c1, c2 in pairs_list[:10]:
        print(f"  Columns ({c1:>2},{c2:>2}): phi = {phi:>6.3f}")

    # Row-coincidence: for each pair of "high-palette" columns (0,2,3,4,5,6),
    # do they have palette at the SAME rows?
    print()
    print("Row-by-row palette coincidence for high-palette columns {0,2,3,4,5,6}:")
    high_cols = [0, 2, 3, 4, 5, 6]
    for r_idx in range(n_rows):
        row_vals = []
        for c in high_cols:
            v = grid_pal[r_idx][c]
            row_vals.append(str(v) if v is not None else ".")
        pal_count = sum(1 for c in high_cols if grid_pal[r_idx][c] == 1)
        print(f"  Row {r_idx}: {' '.join(row_vals)}  ({pal_count}/{len(high_cols)} palette)")

    return phi_matrix

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 6: Row analysis in 7×14 grid
# ══════════════════════════════════════════════════════════════════════════

def analysis_6():
    print()
    print("=" * 80)
    print("ANALYSIS 6: Row palette density in 7x14 grid")
    print("=" * 80)
    print()

    rows = arrange_grid(14)

    print(f"{'Row':>4} {'Positions':>12} {'Pal':>4} {'Total':>5} {'Rate':>7} {'Nulls':>5} {'Cribs':>5}")
    print("-" * 55)

    row_details = []
    for r_idx, row in enumerate(rows):
        pal_count = sum(1 for p in row if is_palette(p))
        null_count = sum(1 for p in row if p in CONSENSUS_NULLS)
        crib_count = sum(1 for p in row if p in CRIB_POSITIONS)
        start, end = row[0], row[-1]
        row_details.append({
            'row': r_idx,
            'start': start,
            'end': end,
            'pal': pal_count,
            'total': len(row),
            'rate': pal_count / len(row),
            'nulls': null_count,
            'cribs': crib_count,
        })
        print(f"{r_idx:>4} {start:>4}-{end:<4}   {pal_count:>4} {len(row):>5} {pal_count/len(row):>7.1%} {null_count:>5} {crib_count:>5}")

    print()

    # Quadrant analysis
    print("Quadrant analysis (top/bottom × left/right):")
    top_rows = rows[:4]  # rows 0-3
    bottom_rows = rows[4:]  # rows 4-6

    quadrants = {
        'TL (rows 0-3, cols 0-6)': [],
        'TR (rows 0-3, cols 7-13)': [],
        'BL (rows 4-6, cols 0-6)': [],
        'BR (rows 4-6, cols 7-13)': [],
    }

    for r_idx, row in enumerate(rows):
        for col_idx, pos in enumerate(row):
            if r_idx < 4:
                if col_idx < 7:
                    quadrants['TL (rows 0-3, cols 0-6)'].append(pos)
                else:
                    quadrants['TR (rows 0-3, cols 7-13)'].append(pos)
            else:
                if col_idx < 7:
                    quadrants['BL (rows 4-6, cols 0-6)'].append(pos)
                else:
                    quadrants['BR (rows 4-6, cols 7-13)'].append(pos)

    print(f"{'Quadrant':>30} {'Pal':>4} {'Total':>5} {'Rate':>7} {'Nulls':>5}")
    print("-" * 55)
    for name, positions in quadrants.items():
        pal = sum(1 for p in positions if is_palette(p))
        nulls = sum(1 for p in positions if p in CONSENSUS_NULLS)
        print(f"{name:>30} {pal:>4} {len(positions):>5} {pal/len(positions):.1%}   {nulls:>5}")

    # Row interaction with column pattern
    print()
    print("Row × column interaction (palette counts in 7x14 grid):")
    print()
    print(f"{'':>6}", end="")
    for c in range(14):
        print(f" c{c:<2}", end="")
    print(" | Sum")
    print("-" * 70)

    col_sums = [0] * 14
    for r_idx, row in enumerate(rows):
        print(f"r{r_idx}:   ", end="")
        row_sum = 0
        for col_idx, pos in enumerate(row):
            val = 1 if is_palette(pos) else 0
            print(f"  {val} ", end="")
            col_sums[col_idx] += val
            row_sum += val
        print(f" | {row_sum}")

    print(f"{'Sum:':>6}", end="")
    for s in col_sums:
        print(f"  {s} ", end="")
    print(f" | {sum(col_sums)}")

    # Statistical test: is there a row x column interaction beyond marginals?
    # Under independence of row and column effects, expected[r,c] = row_sum * col_sum / total
    # This is a post-hoc test of 2D structure
    print()
    print("Testing for row x column interaction (beyond marginal effects):")

    # Build observed matrix
    obs = [[0]*14 for _ in range(7)]
    row_sums = [0]*7
    for r_idx, row in enumerate(rows):
        for col_idx, pos in enumerate(row):
            val = 1 if is_palette(pos) else 0
            obs[r_idx][col_idx] = val
            row_sums[r_idx] += val

    total = sum(col_sums)

    # Expected under independence of row and column marginals
    chi2_interaction = 0
    valid_cells = 0
    for r in range(7):
        for c in range(14):
            if r * 14 + c >= CT_LEN:  # position doesn't exist
                continue
            exp = row_sums[r] * col_sums[c] / total if total > 0 else 0
            if exp > 0:
                chi2_interaction += (obs[r][c] - exp)**2 / exp
                valid_cells += 1

    df_interaction = (7-1) * (14-1) - 1  # approximate, accounting for constraints
    print(f"  Chi-square (interaction) = {chi2_interaction:.2f}")
    print(f"  Valid cells = {valid_cells}, approx df = {df_interaction}")
    print(f"  Chi2/df = {chi2_interaction/df_interaction:.2f}")
    print(f"  (Values near 1.0 indicate no interaction beyond marginals)")

    return row_details

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 4: Interpretive implications
# ══════════════════════════════════════════════════════════════════════════

def analysis_4(analysis_1_results, analysis_2_results, analysis_3_results):
    print()
    print("=" * 80)
    print("ANALYSIS 4: Interpretive assessment and mechanism implications")
    print("=" * 80)
    print()

    # Determine if width=14 is uniquely significant
    w14_result = [r for r in analysis_1_results if r['width'] == 14][0]
    sig_widths = [r['width'] for r in analysis_1_results if r['pval_hyper'] < 0.01]

    print("SUMMARY OF FINDINGS:")
    print()

    # 1. Width specificity
    print("1. WIDTH SPECIFICITY")
    print(f"   Widths with raw p < 0.01: {sig_widths}")
    if len(sig_widths) == 1 and sig_widths[0] == 14:
        print("   -> Width 14 is UNIQUELY significant. Strong grid-specificity.")
    elif 14 in sig_widths:
        print(f"   -> Width 14 is among {len(sig_widths)} significant widths.")
        print(f"      Need to check if others are structurally related (multiples, etc.)")
    else:
        print("   -> Width 14 is NOT among the most significant widths.")
    print()

    # 2. Linear position
    print("2. LINEAR POSITION BIAS")
    r_pb = analysis_2_results['r_pointbiserial']
    pval_cond = analysis_2_results['pval_conditional_width14']
    print(f"   Point-biserial r = {r_pb:.4f}")
    print(f"   Conditional (stratified) p-value = {pval_cond:.6f}")
    if abs(r_pb) > 0.3:
        print("   -> Strong linear bias detected. Grid asymmetry is LARGELY explained by position.")
    elif pval_cond > 0.05:
        print("   -> After controlling for row, grid asymmetry is NOT significant.")
        print("      The effect is driven by which ROWS (= position segments) are palette-heavy.")
    else:
        print("   -> Grid asymmetry SURVIVES position control. There is genuine 2D structure.")
    print()

    # 3. Chi-square optimality
    print("3. OPTIMAL WIDTH")
    top_width = analysis_3_results[0]['width']
    w14_rank = next(i+1 for i, r in enumerate(analysis_3_results) if r['width'] == 14)
    print(f"   Best separation: width {top_width} (chi2 = {analysis_3_results[0]['chi2']:.2f})")
    print(f"   Width 14 rank: #{w14_rank} (chi2 = {[r for r in analysis_3_results if r['width']==14][0]['chi2']:.2f})")
    if top_width == 14:
        print("   -> Width 14 IS the optimal separator. Consistent with grid hypothesis.")
    else:
        print(f"   -> Width {top_width} separates better than 14. Grid may not be primary.")
    print()

    # 4. Structural implications
    print("4. STRUCTURAL IMPLICATIONS")
    print()
    print("   The 7×14 grid has deep structural resonance:")
    print("   - 7 = len(KRYPTOS) = len(palette) = number of rows")
    print("   - 14 = K3 chart width = 2×7")
    print("   - 97+1 = 98 = 7×14 (grid requires exactly one padding position)")
    print("   - 35 palette positions = 7×5 (another K4 structural constant)")
    print()
    print("   However, these numerological coincidences cannot substitute for")
    print("   statistical evidence. The key question is whether the COLUMN-LEVEL")
    print("   palette distribution in this grid carries cryptanalytic information")
    print("   beyond what is already captured by the (pos%7,pos%5) stego rule.")
    print()

    # 5. Connection to known stego structure
    print("5. CONNECTION TO KNOWN STEGO STRUCTURE")
    print()
    print("   The (pos%7,pos%5) classification table already perfectly separates")
    print("   consensus null palette positions from real palette positions.")
    print("   The 7×14 grid has columns = pos%14 and rows = pos//14.")
    print("   Since pos%7 = pos%14 mod 7, the column-level palette asymmetry")
    print("   may simply be the (pos%7,pos%5) stego rule viewed through a")
    print("   14-column lens. If so, width=14 is NOT an independent discovery —")
    print("   it is an algebraic consequence of the mod-7 structure already known.")
    print()
    print("   Specific check: does pos%7 (= column mod 7) explain the asymmetry?")

    # Check: palette rate by pos%7
    mod7_pal = Counter()
    mod7_total = Counter()
    for p in range(CT_LEN):
        mod7_total[p % 7] += 1
        if is_palette(p):
            mod7_pal[p % 7] += 1

    print(f"   {'pos%7':>5} {'Pal':>4} {'Total':>5} {'Rate':>7}")
    for m in range(7):
        print(f"   {m:>5} {mod7_pal[m]:>4} {mod7_total[m]:>5} {mod7_pal[m]/mod7_total[m]:.1%}")

    print()
    print("   In a 14-column grid, columns 0-6 have pos%7 = 0-6,")
    print("   and columns 7-13 have pos%7 = 0-6 (wrapping). So left/right")
    print("   asymmetry requires that palette density VARIES between the two")
    print("   halves even when they share the same pos%7 residues. Let me check...")
    print()

    # For each pos%7 residue, compare palette rate in left half (cols 0-6) vs right half (cols 7-13)
    rows_14 = arrange_grid(14)
    left_by_mod7 = {m: {'pal': 0, 'total': 0} for m in range(7)}
    right_by_mod7 = {m: {'pal': 0, 'total': 0} for m in range(7)}

    for row in rows_14:
        for col_idx, pos in enumerate(row):
            m = pos % 7
            if col_idx < 7:
                left_by_mod7[m]['total'] += 1
                if is_palette(pos):
                    left_by_mod7[m]['pal'] += 1
            else:
                right_by_mod7[m]['total'] += 1
                if is_palette(pos):
                    right_by_mod7[m]['pal'] += 1

    print(f"   {'pos%7':>5} {'Left_pal':>8} {'Left_tot':>8} {'Left%':>6} {'Right_pal':>9} {'Right_tot':>9} {'Right%':>6}")
    for m in range(7):
        lp = left_by_mod7[m]['pal']
        lt = left_by_mod7[m]['total']
        rp = right_by_mod7[m]['pal']
        rt = right_by_mod7[m]['total']
        lr = lp/lt if lt > 0 else 0
        rr = rp/rt if rt > 0 else 0
        print(f"   {m:>5} {lp:>8} {lt:>8} {lr:>6.0%} {rp:>9} {rt:>9} {rr:>6.0%}")

    print()
    print("   If left% >> right% for most pos%7 residues, the asymmetry is")
    print("   NOT explained by pos%7 alone — the 14-column structure adds info.")
    print("   If left% ~ right%, the asymmetry is just pos%7 aliased to columns.")

    # Check: is asymmetry explained by pos%14?
    print()
    print("   Direct check — palette rate by pos%14 (= column in 14-wide grid):")
    mod14_pal = Counter()
    mod14_total = Counter()
    for p in range(CT_LEN):
        mod14_total[p % 14] += 1
        if is_palette(p):
            mod14_pal[p % 14] += 1

    print(f"   {'col':>4} {'Pal':>4} {'Total':>5} {'Rate':>7} {'pos%7':>5}")
    for c in range(14):
        print(f"   {c:>4} {mod14_pal[c]:>4} {mod14_total[c]:>5} {mod14_pal[c]/mod14_total[c]:.1%}   {c%7:>5}")

    # Key test: same pos%7 values appear in both halves.
    # e.g., col0 (pos%7=0) and col7 (pos%7=0). If they differ, it's not just pos%7.
    print()
    print("   Paired columns sharing same pos%7:")
    for m in range(7):
        left_col = m
        right_col = m + 7
        lp = mod14_pal[left_col]
        lt = mod14_total[left_col]
        rp = mod14_pal[right_col]
        rt = mod14_total[right_col]
        diff = lp/lt - rp/rt if lt > 0 and rt > 0 else 0
        print(f"   pos%7={m}: col{left_col}={lp}/{lt}={lp/lt:.0%}  col{right_col}={rp}/{rt}={rp/rt:.0%}  diff={diff:+.0%}")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("RIGOROUS AUDIT: K4 7×14 Grid Palette Asymmetry")
    print("=" * 80)
    print()
    print(f"CT = {CT}")
    print(f"CT length = {CT_LEN}")
    print(f"Palette = {sorted(PALETTE)}")
    print(f"Palette positions = {PAL_POSITIONS}")
    print(f"N palette = {N_PAL}")
    print(f"Palette rate = {N_PAL}/{N_TOTAL} = {N_PAL/N_TOTAL:.1%}")
    print()

    # Verify the claimed finding
    print("VERIFICATION of claimed finding:")
    rows = arrange_grid(14)
    print(f"Grid dimensions: {len(rows)} rows x 14 columns (last row has {len(rows[-1])} chars)")

    col_counts = [0] * 14
    col_totals = [0] * 14
    for row in rows:
        for col_idx, pos in enumerate(row):
            col_totals[col_idx] += 1
            if is_palette(pos):
                col_counts[col_idx] += 1

    print(f"Column:  ", "  ".join(f"{c:>3}" for c in range(14)))
    print(f"Palette: ", "  ".join(f"{col_counts[c]}/{col_totals[c]}" for c in range(14)))
    print(f"Rate:    ", "  ".join(f"{col_counts[c]/col_totals[c]:>3.0%}" for c in range(14)))

    left_pal = sum(col_counts[:7])
    left_total = sum(col_totals[:7])
    right_pal = sum(col_counts[7:])
    right_total = sum(col_totals[7:])

    print(f"\nLeft 7 cols: {left_pal}/{left_total} = {left_pal/left_total:.1%}")
    print(f"Right 7 cols: {right_pal}/{right_total} = {right_pal/right_total:.1%}")
    print(f"Claimed: left=27/49=55%, right=8/48=17%")
    print(f"Verified: left={left_pal}/{left_total}={left_pal/left_total:.1%}, right={right_pal}/{right_total}={right_pal/right_total:.1%}")

    # Run all analyses
    a1_results = analysis_1()
    a2_results = analysis_2()
    a3_results = analysis_3()
    analysis_4(a1_results, a2_results, a3_results)
    phi_matrix = analysis_5()
    row_details = analysis_6()

    # ── Final Summary ──────────────────────────────────────────────────────
    print()
    print("=" * 80)
    print("FINAL STATISTICAL SUMMARY")
    print("=" * 80)
    print()

    w14_hyper = [r for r in a1_results if r['width'] == 14][0]['pval_hyper']
    sig_widths_001 = sorted([r['width'] for r in a1_results if r['pval_hyper'] < 0.01])
    sig_widths_0001 = sorted([r['width'] for r in a1_results if r['pval_hyper'] < 0.001])

    print(f"Width=14 hypergeometric p-value (one-sided): {w14_hyper:.6f}")
    print(f"Widths with p < 0.01: {sig_widths_001}")
    print(f"Widths with p < 0.001: {sig_widths_0001}")
    print()
    print(f"Linear position bias (point-biserial r): {a2_results['r_pointbiserial']:.4f}")
    print(f"Mean palette position: {a2_results['pal_mean']:.1f} vs overall {CT_LEN/2:.1f}")
    print(f"P(palette earlier): {a2_results['pval_early']:.6f}")
    print(f"Width=14 p-value after row stratification: {a2_results['pval_conditional_width14']:.6f}")
    print()

    chi2_rank = next(i+1 for i, r in enumerate(a3_results) if r['width'] == 14)
    print(f"Width=14 chi-square rank: #{chi2_rank} of {len(a3_results)}")
    print()

    # Save results
    output = {
        'analysis_1_significant_widths_p001': sig_widths_001,
        'analysis_1_significant_widths_p0001': sig_widths_0001,
        'width14_hypergeometric_pvalue': w14_hyper,
        'analysis_2_palette_mean_position': a2_results['pal_mean'],
        'analysis_2_point_biserial_r': a2_results['r_pointbiserial'],
        'analysis_2_pval_early': a2_results['pval_early'],
        'analysis_2_conditional_pval': a2_results['pval_conditional_width14'],
        'analysis_3_chi2_rank_width14': chi2_rank,
        'analysis_3_top5': [(r['width'], r['chi2']) for r in a3_results[:5]],
    }

    results_path = os.path.join(_ROOT, "results", "e_grid_asymmetry_audit.json")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {results_path}")
