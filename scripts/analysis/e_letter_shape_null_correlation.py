#!/usr/bin/env python3
"""
Letter Shape vs Null Position Correlation Analysis
===================================================
Cipher: N/A (physical/statistical analysis)
Family: analysis
Status: active
Keyspace: N/A (26 letters × 9 features)
Last run: never
Best score: N/A

Tests the hypothesis that geometric properties of letter SHAPES correlate
with null-position probability in K4's consensus null mask. The null palette
{B,G,I,K,O,W,Z} may correspond to letters whose physical projections
through copper cutouts are least legible under angular illumination.
"""

import json
import math
import os
import sys
import random
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN

# ── Constants ──────────────────────────────────────────────────────────────

CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
NULL_PALETTE = set("BGIKOWZ")

# 6 distinct masks from the 15/24 runs (from memory files)
# These are the masks that achieve 15/24 on DEFECTOR:AZ_beau+col7
# For frequency analysis we use the consensus set for binary and
# model all 97 positions as null/non-null
MASK_SETS = [
    # We only have the 17 consensus positions confirmed across all 6.
    # For per-position frequency we use the binary consensus.
]

# ── Letter Geometric Feature Database ──────────────────────────────────────
# Features for standard uppercase block/sans-serif letters (as cut into copper)
# Each letter gets a dict of measurable geometric properties.

LETTER_FEATURES = {
    # Format: {
    #   'counters': enclosed regions (holes),
    #   'terminals': stroke endpoints,
    #   'h_sym': horizontal symmetry (left-right mirror),
    #   'v_sym': vertical symmetry (top-bottom mirror),
    #   'diagonals': number of diagonal strokes,
    #   'curves': number of curved segments,
    #   'strokes': approximate total stroke segments,
    #   'width_class': 0=narrow, 1=normal, 2=wide,
    #   'sharp_angles': interior angles < 90 degrees,
    #   'min_gap': minimum internal gap width (0=no gap, 1=small, 2=medium, 3=large)
    #             (how thin the thinnest internal feature is — critical for projection)
    # }
    'A': {'counters': 1, 'terminals': 2, 'h_sym': True,  'v_sym': False, 'diagonals': 2, 'curves': 0, 'strokes': 3, 'width_class': 1, 'sharp_angles': 1, 'min_gap': 1},
    'B': {'counters': 2, 'terminals': 0, 'h_sym': False, 'v_sym': False, 'diagonals': 0, 'curves': 2, 'strokes': 3, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 1},
    'C': {'counters': 0, 'terminals': 2, 'h_sym': False, 'v_sym': False, 'diagonals': 0, 'curves': 1, 'strokes': 1, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 3},
    'D': {'counters': 1, 'terminals': 0, 'h_sym': False, 'v_sym': False, 'diagonals': 0, 'curves': 1, 'strokes': 2, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 2},
    'E': {'counters': 0, 'terminals': 3, 'h_sym': False, 'v_sym': False, 'diagonals': 0, 'curves': 0, 'strokes': 4, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 2},
    'F': {'counters': 0, 'terminals': 3, 'h_sym': False, 'v_sym': False, 'diagonals': 0, 'curves': 0, 'strokes': 3, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 2},
    'G': {'counters': 0, 'terminals': 2, 'h_sym': False, 'v_sym': False, 'diagonals': 0, 'curves': 1, 'strokes': 2, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 2},
    'H': {'counters': 0, 'terminals': 4, 'h_sym': True,  'v_sym': True,  'diagonals': 0, 'curves': 0, 'strokes': 3, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 2},
    'I': {'counters': 0, 'terminals': 2, 'h_sym': True,  'v_sym': True,  'diagonals': 0, 'curves': 0, 'strokes': 1, 'width_class': 0, 'sharp_angles': 0, 'min_gap': 3},
    'J': {'counters': 0, 'terminals': 2, 'h_sym': False, 'v_sym': False, 'diagonals': 0, 'curves': 1, 'strokes': 1, 'width_class': 0, 'sharp_angles': 0, 'min_gap': 3},
    'K': {'counters': 0, 'terminals': 4, 'h_sym': False, 'v_sym': False, 'diagonals': 2, 'curves': 0, 'strokes': 3, 'width_class': 1, 'sharp_angles': 2, 'min_gap': 2},
    'L': {'counters': 0, 'terminals': 2, 'h_sym': False, 'v_sym': False, 'diagonals': 0, 'curves': 0, 'strokes': 2, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 3},
    'M': {'counters': 0, 'terminals': 2, 'h_sym': True,  'v_sym': False, 'diagonals': 2, 'curves': 0, 'strokes': 4, 'width_class': 2, 'sharp_angles': 2, 'min_gap': 2},
    'N': {'counters': 0, 'terminals': 2, 'h_sym': False, 'v_sym': False, 'diagonals': 1, 'curves': 0, 'strokes': 3, 'width_class': 1, 'sharp_angles': 1, 'min_gap': 2},
    'O': {'counters': 1, 'terminals': 0, 'h_sym': True,  'v_sym': True,  'diagonals': 0, 'curves': 1, 'strokes': 1, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 2},
    'P': {'counters': 1, 'terminals': 1, 'h_sym': False, 'v_sym': False, 'diagonals': 0, 'curves': 1, 'strokes': 2, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 1},
    'Q': {'counters': 1, 'terminals': 1, 'h_sym': False, 'v_sym': False, 'diagonals': 1, 'curves': 1, 'strokes': 2, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 2},
    'R': {'counters': 1, 'terminals': 2, 'h_sym': False, 'v_sym': False, 'diagonals': 1, 'curves': 1, 'strokes': 3, 'width_class': 1, 'sharp_angles': 1, 'min_gap': 1},
    'S': {'counters': 0, 'terminals': 2, 'h_sym': False, 'v_sym': False, 'diagonals': 0, 'curves': 2, 'strokes': 1, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 2},
    'T': {'counters': 0, 'terminals': 3, 'h_sym': True,  'v_sym': False, 'diagonals': 0, 'curves': 0, 'strokes': 2, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 3},
    'U': {'counters': 0, 'terminals': 2, 'h_sym': True,  'v_sym': False, 'diagonals': 0, 'curves': 1, 'strokes': 1, 'width_class': 1, 'sharp_angles': 0, 'min_gap': 2},
    'V': {'counters': 0, 'terminals': 2, 'h_sym': True,  'v_sym': False, 'diagonals': 2, 'curves': 0, 'strokes': 2, 'width_class': 1, 'sharp_angles': 1, 'min_gap': 2},
    'W': {'counters': 0, 'terminals': 2, 'h_sym': True,  'v_sym': False, 'diagonals': 4, 'curves': 0, 'strokes': 4, 'width_class': 2, 'sharp_angles': 2, 'min_gap': 1},
    'X': {'counters': 0, 'terminals': 4, 'h_sym': True,  'v_sym': True,  'diagonals': 2, 'curves': 0, 'strokes': 2, 'width_class': 1, 'sharp_angles': 2, 'min_gap': 2},
    'Y': {'counters': 0, 'terminals': 3, 'h_sym': True,  'v_sym': False, 'diagonals': 2, 'curves': 0, 'strokes': 3, 'width_class': 1, 'sharp_angles': 1, 'min_gap': 2},
    'Z': {'counters': 0, 'terminals': 2, 'h_sym': False, 'v_sym': False, 'diagonals': 1, 'curves': 0, 'strokes': 3, 'width_class': 1, 'sharp_angles': 2, 'min_gap': 2},
}

FEATURE_NAMES = ['counters', 'terminals', 'h_sym', 'v_sym', 'diagonals', 'curves', 'strokes', 'width_class', 'sharp_angles', 'min_gap']


def feature_vector(letter):
    """Return numeric feature vector for a letter."""
    f = LETTER_FEATURES[letter]
    return [f[name] if not isinstance(f[name], bool) else int(f[name]) for name in FEATURE_NAMES]


# ── Shadow Projection Model ───────────────────────────────────────────────
# Model: letter cut out of 3/8" (9.5mm) copper plate. Light passes through.
# At angle theta from perpendicular:
#   - Vertical strokes: shadow width *= cos(theta) (gets thinner)
#   - Horizontal strokes: unaffected
#   - Counter openings: project as ellipse with minor axis *= cos(theta)
#   - Min internal gap: shrinks by cos(theta) — key factor for legibility
# Legibility degrades when the smallest projected feature falls below a threshold.

# For each letter, compute its "critical angle" — the angle at which
# the letter becomes illegible (smallest feature < threshold).

# We model letter legibility as a function of its geometric complexity
# and minimum feature size.

# Letter dimensions (simplified, relative units, based on standard block uppercase)
# width, min_internal_gap_width (relative to letter height = 1.0)
LETTER_DIMENSIONS = {
    # Letter: (overall_width, min_internal_horizontal_gap, min_internal_vertical_gap,
    #          has_counter, counter_min_width)
    # Gaps measured in relative units where letter height = 1.0
    'A': (0.65, 0.25, 0.35, True, 0.25),   # counter at top, narrow
    'B': (0.60, 0.10, 0.20, True, 0.18),   # two small counters
    'C': (0.60, 0.40, 0.60, False, 0.0),   # open, no counter
    'D': (0.65, 0.30, 0.40, True, 0.30),   # one large counter
    'E': (0.55, 0.25, 0.30, False, 0.0),   # horizontal gaps between arms
    'F': (0.55, 0.30, 0.45, False, 0.0),   # like E but open at bottom
    'G': (0.65, 0.25, 0.30, False, 0.0),   # curved with horizontal spur
    'H': (0.65, 0.30, 0.40, False, 0.0),   # two verticals + crossbar
    'I': (0.10, 0.80, 0.80, False, 0.0),   # single thin vertical (or with serifs: 0.30)
    'J': (0.40, 0.50, 0.60, False, 0.0),   # thin, mostly open
    'K': (0.60, 0.15, 0.25, False, 0.0),   # angled strokes meet vertical
    'L': (0.50, 0.45, 0.60, False, 0.0),   # very open, simple
    'M': (0.80, 0.15, 0.35, False, 0.0),   # wide, internal V gaps
    'N': (0.65, 0.20, 0.35, False, 0.0),   # diagonal splits space
    'O': (0.65, 0.20, 0.40, True, 0.20),   # single large counter
    'P': (0.60, 0.15, 0.35, True, 0.18),   # small counter at top
    'Q': (0.65, 0.20, 0.40, True, 0.20),   # like O with tail
    'R': (0.60, 0.12, 0.25, True, 0.15),   # small counter + leg
    'S': (0.55, 0.15, 0.25, False, 0.0),   # double curve, narrow gaps
    'T': (0.60, 0.55, 0.60, False, 0.0),   # very open, crossbar + stem
    'U': (0.65, 0.30, 0.50, False, 0.0),   # open at top
    'V': (0.65, 0.10, 0.50, False, 0.0),   # narrow at bottom
    'W': (0.85, 0.08, 0.35, False, 0.0),   # wide, very narrow internal V's
    'X': (0.60, 0.15, 0.30, False, 0.0),   # crossing strokes
    'Y': (0.60, 0.20, 0.35, False, 0.0),   # like V on a stem
    'Z': (0.55, 0.15, 0.30, False, 0.0),   # diagonal between parallels
}


def projection_legibility(letter, theta_deg):
    """
    Compute legibility score at projection angle theta (degrees from perpendicular).

    When light hits the copper at angle theta, horizontal features stay the same
    but vertical/horizontal gaps change depending on the light direction.

    For simplicity, model the "worst case" — light along horizontal axis.
    Vertical strokes project normally but horizontal gaps shrink by cos(theta).
    Counter openings shrink in one dimension.

    Returns a legibility score (0 = illegible, 1 = fully legible).
    """
    theta_rad = math.radians(theta_deg)
    cos_t = max(math.cos(theta_rad), 0.001)

    dims = LETTER_DIMENSIONS[letter]
    overall_w, min_h_gap, min_v_gap, has_counter, counter_min_w = dims

    # At angle theta from perpendicular (horizontal light direction):
    # - Horizontal gaps (between vertically-stacked features) shrink: gap * cos(theta)
    # - But the KEY effect for copper cutouts: light must pass through the copper thickness
    #   At angle, the effective thickness the light traverses = thickness / cos(theta)
    #   This means the cutout effectively narrows: effective_gap = actual_gap - thickness * tan(theta)

    # Copper thickness: 3/8" = 9.5mm. Letter height ~15mm (small sculpture letters)
    # Relative thickness = 9.5/15 = 0.633 of letter height
    # At angle theta, the "lost width" in a gap = thickness * tan(theta) (relative)

    RELATIVE_THICKNESS = 0.633  # copper thickness / letter height

    tan_t = math.tan(theta_rad) if theta_deg < 89 else 100.0
    gap_loss = RELATIVE_THICKNESS * tan_t

    # Effective minimum gap (horizontal direction, for angular light):
    effective_h_gap = max(min_h_gap - gap_loss, 0.0)

    # Counter: projects as ellipse, minor axis shrinks
    effective_counter = max(counter_min_w - gap_loss, 0.0) if has_counter else 1.0

    # Overall width of letter visible (outside edges) — mostly OK at angles
    # but thin letters (I) lose their entire width
    effective_width = max(overall_w - gap_loss, 0.0)

    # Legibility = minimum of (normalized gap/width scores)
    # A feature is "legible" if its effective size is > some threshold
    LEGIBILITY_THRESHOLD = 0.05  # below this = illegible

    scores = []
    if min_h_gap > 0:
        scores.append(min(effective_h_gap / min_h_gap, 1.0) if min_h_gap > 0 else 1.0)
    if has_counter:
        scores.append(min(effective_counter / counter_min_w, 1.0) if counter_min_w > 0 else 1.0)
    scores.append(min(effective_width / overall_w, 1.0) if overall_w > 0 else 0.0)

    # Overall legibility is the MINIMUM feature score (weakest link)
    leg = min(scores) if scores else 0.0

    return max(leg, 0.0)


def critical_angle(letter, threshold=0.1):
    """
    Find the angle (degrees) at which letter legibility drops below threshold.
    Lower = becomes illegible sooner = harder to project.
    """
    for angle in range(0, 90):
        if projection_legibility(letter, angle) < threshold:
            return angle
    return 90  # still legible at 89 degrees


# ── Statistical Tests (stdlib only) ───────────────────────────────────────

def mann_whitney_u(x, y):
    """
    Mann-Whitney U test (two-sided).
    Returns (U statistic, approximate p-value using normal approximation).
    """
    nx, ny = len(x), len(y)
    if nx == 0 or ny == 0:
        return float('nan'), 1.0

    # Combine and rank
    combined = [(v, 'x', i) for i, v in enumerate(x)] + [(v, 'y', i) for i, v in enumerate(y)]
    combined.sort(key=lambda t: t[0])

    # Assign ranks (handle ties with average rank)
    ranks = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i
        while j < len(combined) and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + j + 1) / 2.0  # 1-indexed average
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j

    # Sum ranks for group x
    R_x = sum(ranks[k] for k in range(len(combined)) if combined[k][1] == 'x')

    U = R_x - nx * (nx + 1) / 2.0

    # Normal approximation
    mu = nx * ny / 2.0
    sigma = math.sqrt(nx * ny * (nx + ny + 1) / 12.0)
    if sigma == 0:
        return U, 1.0
    z = (U - mu) / sigma
    # Two-sided p-value from normal approximation
    p = 2.0 * (1.0 - _norm_cdf(abs(z)))
    return U, p


def _norm_cdf(x):
    """Standard normal CDF approximation (Abramowitz & Stegun)."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def fisher_exact_2x2(a, b, c, d):
    """
    Fisher's exact test for 2x2 table:
        [[a, b],
         [c, d]]
    Returns (odds_ratio, p_value) using the hypergeometric distribution.
    Two-sided p-value computed by summing probabilities of tables as extreme or more.
    """
    n = a + b + c + d

    def log_choose(n, k):
        if k < 0 or k > n:
            return float('-inf')
        return sum(math.log(n - i) - math.log(i + 1) for i in range(min(k, n - k)))

    def hypergeom_pmf(k, N, K, n):
        """P(X=k) for hypergeometric distribution."""
        log_p = log_choose(K, k) + log_choose(N - K, n - k) - log_choose(N, n)
        return math.exp(log_p)

    row1 = a + b
    row2 = c + d
    col1 = a + c

    # Observed probability
    p_obs = hypergeom_pmf(a, n, row1, col1)

    # Two-sided: sum all probabilities <= p_obs
    p_value = 0.0
    for k in range(max(0, col1 - row2), min(row1, col1) + 1):
        p_k = hypergeom_pmf(k, n, row1, col1)
        if p_k <= p_obs * 1.0001:  # small tolerance for floating point
            p_value += p_k

    # Odds ratio
    if b * c == 0:
        odds_ratio = float('inf') if a * d > 0 else 0.0
    else:
        odds_ratio = (a * d) / (b * c)

    return odds_ratio, min(p_value, 1.0)


def point_biserial(binary, continuous):
    """
    Point-biserial correlation between a binary variable and a continuous one.
    binary: list of 0/1 values
    continuous: list of numeric values
    Returns (r, approximate p-value).
    """
    n = len(binary)
    assert n == len(continuous)

    group0 = [continuous[i] for i in range(n) if binary[i] == 0]
    group1 = [continuous[i] for i in range(n) if binary[i] == 1]

    if not group0 or not group1:
        return 0.0, 1.0

    n0, n1 = len(group0), len(group1)
    m0 = sum(group0) / n0
    m1 = sum(group1) / n1

    # Overall std dev
    m_all = sum(continuous) / n
    s = math.sqrt(sum((x - m_all) ** 2 for x in continuous) / n)
    if s == 0:
        return 0.0, 1.0

    r = (m1 - m0) / s * math.sqrt(n0 * n1 / (n * n))

    # t-test approximation for significance
    if abs(r) >= 1.0:
        return r, 0.0
    t = r * math.sqrt((n - 2) / (1 - r * r))
    # Approximate p-value from t-distribution (normal approx for large n)
    p = 2.0 * (1.0 - _norm_cdf(abs(t)))

    return r, p


# ── Main Analysis ──────────────────────────────────────────────────────────

def run_analysis():
    results = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'ciphertext': CT,
        'ct_length': CT_LEN,
        'consensus_null_positions': sorted(CONSENSUS_NULLS),
        'null_palette': sorted(NULL_PALETTE),
    }

    print("=" * 78)
    print("Letter Shape vs Null Position Correlation Analysis")
    print("=" * 78)
    print()

    # ── 1. Feature Table ───────────────────────────────────────────────────
    print("1. LETTER GEOMETRIC FEATURES")
    print("-" * 78)

    # Header
    hdr = f"{'Ltr':>3} {'Cnt':>3} {'Trm':>3} {'HSy':>3} {'VSy':>3} {'Dia':>3} {'Crv':>3} {'Stk':>3} {'Wid':>3} {'Shp':>3} {'Gap':>3} {'Pal':>3} {'CrA':>4}"
    print(hdr)
    print("-" * len(hdr))

    feature_table = {}
    for letter in sorted(LETTER_FEATURES.keys()):
        f = LETTER_FEATURES[letter]
        ca = critical_angle(letter)
        is_pal = "YES" if letter in NULL_PALETTE else "no"
        feature_table[letter] = {
            'features': {name: (int(f[name]) if isinstance(f[name], bool) else f[name]) for name in FEATURE_NAMES},
            'critical_angle': ca,
            'is_palette': letter in NULL_PALETTE,
        }
        print(f"{letter:>3} {f['counters']:>3} {f['terminals']:>3} {int(f['h_sym']):>3} {int(f['v_sym']):>3} "
              f"{f['diagonals']:>3} {f['curves']:>3} {f['strokes']:>3} {f['width_class']:>3} "
              f"{f['sharp_angles']:>3} {f['min_gap']:>3} {is_pal:>3} {ca:>4}")

    results['feature_table'] = feature_table

    # ── 2. Per-Position Analysis ────────────────────────────────────────────
    print()
    print("2. PER-POSITION ANALYSIS")
    print("-" * 78)

    position_data = []
    for i, ch in enumerate(CT):
        is_null = i in CONSENSUS_NULLS
        is_palette = ch in NULL_PALETTE
        position_data.append({
            'pos': i,
            'letter': ch,
            'is_null': is_null,
            'is_palette': is_palette,
            'features': feature_vector(ch),
            'critical_angle': critical_angle(ch),
        })

    # Summary: letter frequency at null vs non-null positions
    null_letters = [CT[i] for i in range(CT_LEN) if i in CONSENSUS_NULLS]
    nonnull_letters = [CT[i] for i in range(CT_LEN) if i not in CONSENSUS_NULLS]

    null_freq = Counter(null_letters)
    nonnull_freq = Counter(nonnull_letters)

    print(f"\nNull positions ({len(CONSENSUS_NULLS)}): letters = {dict(null_freq)}")
    print(f"Non-null positions ({CT_LEN - len(CONSENSUS_NULLS)}): {len(nonnull_freq)} distinct letters")
    print(f"Null palette: {sorted(NULL_PALETTE)} ({len(NULL_PALETTE)} letters)")
    print(f"Non-null letters in CT: {sorted(set(nonnull_letters) - NULL_PALETTE)}")

    # ── 3. Statistical Tests ───────────────────────────────────────────────
    print()
    print("3. STATISTICAL TESTS")
    print("=" * 78)

    # Binary arrays for each position
    null_binary = [1 if i in CONSENSUS_NULLS else 0 for i in range(CT_LEN)]

    stat_results = {}

    # 3a. Mann-Whitney U for each feature: null positions vs non-null positions
    print("\n3a. Mann-Whitney U: feature values at null vs non-null positions")
    print(f"{'Feature':<15} {'Null mean':>10} {'Non-null mean':>13} {'U':>10} {'p-value':>10} {'Direction':>12}")
    print("-" * 75)

    for fi, fname in enumerate(FEATURE_NAMES):
        null_vals = [position_data[i]['features'][fi] for i in range(CT_LEN) if i in CONSENSUS_NULLS]
        nonnull_vals = [position_data[i]['features'][fi] for i in range(CT_LEN) if i not in CONSENSUS_NULLS]

        U, p = mann_whitney_u(null_vals, nonnull_vals)
        null_mean = sum(null_vals) / len(null_vals) if null_vals else 0
        nonnull_mean = sum(nonnull_vals) / len(nonnull_vals) if nonnull_vals else 0
        direction = "null>nonnull" if null_mean > nonnull_mean else ("null<nonnull" if null_mean < nonnull_mean else "equal")
        sig = "  *" if p < 0.05 else ("  ." if p < 0.10 else "")

        stat_results[f'mw_{fname}'] = {'U': U, 'p': p, 'null_mean': null_mean, 'nonnull_mean': nonnull_mean, 'direction': direction}
        print(f"{fname:<15} {null_mean:>10.3f} {nonnull_mean:>13.3f} {U:>10.1f} {p:>10.4f} {direction:>12}{sig}")

    # Also test critical_angle
    null_ca = [position_data[i]['critical_angle'] for i in range(CT_LEN) if i in CONSENSUS_NULLS]
    nonnull_ca = [position_data[i]['critical_angle'] for i in range(CT_LEN) if i not in CONSENSUS_NULLS]
    U, p = mann_whitney_u(null_ca, nonnull_ca)
    null_ca_mean = sum(null_ca) / len(null_ca)
    nonnull_ca_mean = sum(nonnull_ca) / len(nonnull_ca)
    direction = "null>nonnull" if null_ca_mean > nonnull_ca_mean else "null<nonnull"
    sig = "  *" if p < 0.05 else ("  ." if p < 0.10 else "")
    stat_results['mw_critical_angle'] = {'U': U, 'p': p, 'null_mean': null_ca_mean, 'nonnull_mean': nonnull_ca_mean, 'direction': direction}
    print(f"{'critical_angle':<15} {null_ca_mean:>10.3f} {nonnull_ca_mean:>13.3f} {U:>10.1f} {p:>10.4f} {direction:>12}{sig}")

    # 3b. Point-biserial correlations
    print("\n3b. Point-biserial correlation: feature vs null status")
    print(f"{'Feature':<15} {'r':>10} {'p-value':>10}")
    print("-" * 40)

    pb_results = {}
    for fi, fname in enumerate(FEATURE_NAMES):
        cont = [position_data[i]['features'][fi] for i in range(CT_LEN)]
        r, p = point_biserial(null_binary, cont)
        pb_results[fname] = {'r': r, 'p': p}
        sig = "  *" if p < 0.05 else ("  ." if p < 0.10 else "")
        print(f"{fname:<15} {r:>10.4f} {p:>10.4f}{sig}")

    # Critical angle
    cont_ca = [position_data[i]['critical_angle'] for i in range(CT_LEN)]
    r, p = point_biserial(null_binary, cont_ca)
    pb_results['critical_angle'] = {'r': r, 'p': p}
    sig = "  *" if p < 0.05 else ("  ." if p < 0.10 else "")
    print(f"{'critical_angle':<15} {r:>10.4f} {p:>10.4f}{sig}")

    stat_results['point_biserial'] = pb_results

    # 3c. Fisher's exact test: palette features vs non-palette
    print("\n3c. Fisher's exact test: feature enrichment in palette vs non-palette")
    print(f"{'Feature':<15} {'Threshold':>9} {'Pal+':>5} {'Pal-':>5} {'Non+':>5} {'Non-':>5} {'OR':>8} {'p-value':>10}")
    print("-" * 73)

    fisher_results = {}
    for fname in FEATURE_NAMES:
        # For binary features, use the feature directly
        pal_vals = [LETTER_FEATURES[ch][fname] for ch in NULL_PALETTE]
        nonpal_vals = [LETTER_FEATURES[ch][fname] for ch in sorted(set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") - NULL_PALETTE)]

        if fname in ('h_sym', 'v_sym'):
            threshold = 0.5  # binary
        elif fname == 'counters':
            threshold = 0.5  # has counter or not
        elif fname == 'width_class':
            threshold = 0.5  # narrow (0) vs normal/wide (1,2)
        elif fname == 'min_gap':
            threshold = 1.5  # small gap (<=1) vs larger (>=2)
        else:
            # Use median as threshold
            all_vals = pal_vals + nonpal_vals
            sorted_vals = sorted(all_vals)
            threshold = sorted_vals[len(sorted_vals) // 2] - 0.01

        pal_above = sum(1 for v in pal_vals if (int(v) if isinstance(v, bool) else v) > threshold)
        pal_below = len(pal_vals) - pal_above
        nonpal_above = sum(1 for v in nonpal_vals if (int(v) if isinstance(v, bool) else v) > threshold)
        nonpal_below = len(nonpal_vals) - nonpal_above

        OR, p = fisher_exact_2x2(pal_above, pal_below, nonpal_above, nonpal_below)
        sig = "  *" if p < 0.05 else ("  ." if p < 0.10 else "")
        fisher_results[fname] = {'threshold': threshold, 'OR': OR, 'p': p,
                                  'table': [pal_above, pal_below, nonpal_above, nonpal_below]}
        print(f"{fname:<15} {threshold:>9.1f} {pal_above:>5} {pal_below:>5} {nonpal_above:>5} {nonpal_below:>5} {OR:>8.2f} {p:>10.4f}{sig}")

    stat_results['fisher'] = fisher_results
    results['statistical_tests'] = stat_results

    # ── 4. Shadow Projection Model ─────────────────────────────────────────
    print()
    print("4. SHADOW PROJECTION MODEL")
    print("=" * 78)

    print("\nCritical angle (degrees) where letter becomes illegible (lower = worse):")
    print(f"{'Letter':>6} {'CritAngle':>10} {'Palette':>8}")
    print("-" * 28)

    ca_data = []
    for letter in sorted(LETTER_FEATURES.keys()):
        ca = critical_angle(letter)
        is_pal = "YES" if letter in NULL_PALETTE else ""
        ca_data.append((letter, ca, letter in NULL_PALETTE))
        print(f"{letter:>6} {ca:>10} {is_pal:>8}")

    # Sort by critical angle
    ca_sorted = sorted(ca_data, key=lambda x: x[1])

    print("\nRanking by projection difficulty (lowest critical angle = hardest to read):")
    print(f"{'Rank':>4} {'Letter':>6} {'CritAngle':>10} {'Palette':>8}")
    print("-" * 32)
    for rank, (letter, ca, is_pal) in enumerate(ca_sorted, 1):
        marker = " <-- PALETTE" if is_pal else ""
        print(f"{rank:>4} {letter:>6} {ca:>10}{marker}")

    # How many of the bottom N are palette letters?
    results['projection_ranking'] = [{'letter': l, 'critical_angle': ca, 'is_palette': ip} for l, ca, ip in ca_sorted]

    palette_ranks = [i for i, (l, ca, ip) in enumerate(ca_sorted) if ip]
    avg_palette_rank = sum(palette_ranks) / len(palette_ranks) if palette_ranks else 0
    avg_nonpalette_rank = sum(i for i, (l, ca, ip) in enumerate(ca_sorted) if not ip) / (26 - len(palette_ranks))

    print(f"\nPalette avg rank: {avg_palette_rank:.1f} / 25  (lower = harder to project)")
    print(f"Non-palette avg rank: {avg_nonpalette_rank:.1f} / 25")

    # Rank-sum test on critical angles
    pal_ca = [ca for l, ca, ip in ca_data if ip]
    nonpal_ca = [ca for l, ca, ip in ca_data if not ip]
    U, p = mann_whitney_u(pal_ca, nonpal_ca)
    print(f"Mann-Whitney U (palette vs non-palette critical angles): U={U:.1f}, p={p:.4f}")
    sig_label = "SIGNIFICANT (p<0.05)" if p < 0.05 else ("marginal (p<0.10)" if p < 0.10 else "NOT significant")
    print(f"  --> {sig_label}")

    results['projection_test'] = {
        'palette_avg_rank': avg_palette_rank,
        'nonpalette_avg_rank': avg_nonpalette_rank,
        'palette_mean_critical_angle': sum(pal_ca) / len(pal_ca),
        'nonpalette_mean_critical_angle': sum(nonpal_ca) / len(nonpal_ca),
        'mann_whitney_U': U,
        'mann_whitney_p': p,
    }

    # Legibility curves at various angles
    print("\nLegibility scores at selected angles:")
    angles = [0, 10, 20, 30, 40, 50, 60, 70, 80]
    print(f"{'Letter':>6} " + " ".join(f"{a:>5}" for a in angles) + "  Palette")
    print("-" * (8 + 6 * len(angles) + 10))

    legibility_curves = {}
    for letter in sorted(LETTER_FEATURES.keys()):
        scores = [projection_legibility(letter, a) for a in angles]
        is_pal = "YES" if letter in NULL_PALETTE else ""
        legibility_curves[letter] = {str(a): s for a, s in zip(angles, scores)}
        print(f"{letter:>6} " + " ".join(f"{s:>5.2f}" for s in scores) + f"  {is_pal}")

    results['legibility_curves'] = legibility_curves

    # ── 5. Control Analysis ────────────────────────────────────────────────
    print()
    print("5. CONTROL ANALYSIS")
    print("=" * 78)

    # 5a. Frequency control: are palette letters just common?
    ct_freq = Counter(CT)
    print("\n5a. Letter frequency in K4 ciphertext:")
    print(f"{'Letter':>6} {'Count':>5} {'Palette':>8}")
    print("-" * 23)

    pal_total = sum(ct_freq[ch] for ch in NULL_PALETTE)
    for ch, count in ct_freq.most_common():
        is_pal = "YES" if ch in NULL_PALETTE else ""
        print(f"{ch:>6} {count:>5} {is_pal:>8}")

    print(f"\nPalette letters total occurrences: {pal_total}/{CT_LEN} ({100*pal_total/CT_LEN:.1f}%)")
    print(f"Null positions: {len(CONSENSUS_NULLS)}/{CT_LEN} ({100*len(CONSENSUS_NULLS)/CT_LEN:.1f}%)")
    print(f"Expected nulls from palette frequency alone: {pal_total * len(CONSENSUS_NULLS)/CT_LEN:.1f}")

    # 5b. Monte Carlo: How often does a random 17-of-97 mask produce a palette of size 7 or fewer?
    print("\n5b. Monte Carlo control: random 17-of-97 null masks")
    N_MC = 100_000
    random.seed(42)

    palette_sizes = []
    palette_matches_7_or_fewer = 0
    palette_exactly_matches = 0

    for _ in range(N_MC):
        mask = set(random.sample(range(CT_LEN), len(CONSENSUS_NULLS)))
        letters = set(CT[i] for i in mask)
        palette_sizes.append(len(letters))
        if len(letters) <= len(NULL_PALETTE):
            palette_matches_7_or_fewer += 1
        if letters == NULL_PALETTE:
            palette_exactly_matches += 1

    avg_palette_size = sum(palette_sizes) / N_MC
    p_le7 = palette_matches_7_or_fewer / N_MC
    p_exact = palette_exactly_matches / N_MC

    print(f"  Trials: {N_MC:,}")
    print(f"  Average palette size for random mask: {avg_palette_size:.2f}")
    print(f"  P(palette size <= 7): {p_le7:.6f} ({palette_matches_7_or_fewer}/{N_MC})")
    print(f"  P(palette == exact set): {p_exact:.6f} ({palette_exactly_matches}/{N_MC})")

    results['monte_carlo_control'] = {
        'trials': N_MC,
        'avg_palette_size': avg_palette_size,
        'p_palette_le_7': p_le7,
        'p_exact_match': p_exact,
    }

    # 5c. Do geometric features predict null position BEYOND what letter frequency explains?
    print("\n5c. Geometric features vs null: controlling for letter frequency")
    print("   (Comparing null-rate by geometric feature, among letters with similar frequency)")

    # Group letters by frequency
    freq_groups = {}
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        f = ct_freq.get(ch, 0)
        # Group: 0, 1-2, 3-5, 6+
        if f == 0:
            g = "absent"
        elif f <= 2:
            g = "rare(1-2)"
        elif f <= 5:
            g = "mid(3-5)"
        else:
            g = "freq(6+)"
        freq_groups.setdefault(g, []).append(ch)

    print(f"\n  Frequency groups:")
    for g, letters in sorted(freq_groups.items()):
        pal_in_group = [l for l in letters if l in NULL_PALETTE]
        print(f"    {g}: {sorted(letters)} (palette: {sorted(pal_in_group)})")

    # For each frequency group with both palette and non-palette letters,
    # compare geometric features
    for g, letters in sorted(freq_groups.items()):
        pal = [l for l in letters if l in NULL_PALETTE]
        nonpal = [l for l in letters if l not in NULL_PALETTE]
        if pal and nonpal:
            print(f"\n  Within '{g}' group:")
            for fname in FEATURE_NAMES + ['critical_angle']:
                if fname == 'critical_angle':
                    pal_vals = [critical_angle(l) for l in pal]
                    nonpal_vals = [critical_angle(l) for l in nonpal]
                else:
                    pal_vals = [int(LETTER_FEATURES[l][fname]) if isinstance(LETTER_FEATURES[l][fname], bool) else LETTER_FEATURES[l][fname] for l in pal]
                    nonpal_vals = [int(LETTER_FEATURES[l][fname]) if isinstance(LETTER_FEATURES[l][fname], bool) else LETTER_FEATURES[l][fname] for l in nonpal]
                pal_m = sum(pal_vals) / len(pal_vals)
                nonpal_m = sum(nonpal_vals) / len(nonpal_vals)
                diff = pal_m - nonpal_m
                if abs(diff) > 0.01:
                    print(f"    {fname}: palette={pal_m:.2f}, nonpal={nonpal_m:.2f}, diff={diff:+.2f}")

    # ── 6. Composite Legibility Score ──────────────────────────────────────
    print()
    print("6. COMPOSITE ANALYSIS")
    print("=" * 78)

    # Composite: weighted sum of features correlated with null status
    # Use sign of point-biserial correlation as direction
    print("\nComposite letter 'projection difficulty' score:")
    print("(Higher = more geometric complexity / harder to project)")

    # Simple composite: counters + (3 - min_gap) + sharp_angles + strokes - terminals
    # (features where palette letters might score higher)
    composite = {}
    for letter in sorted(LETTER_FEATURES.keys()):
        f = LETTER_FEATURES[letter]
        # Features that make projection harder:
        score = (f['counters'] * 2          # enclosed regions block light
                 + (3 - f['min_gap'])        # smaller gap = harder
                 + f['sharp_angles']         # sharp angles create thin projections
                 + f['strokes'] * 0.5        # more strokes = more complex
                 + f['diagonals'] * 0.5      # diagonals create varying thickness
                 - f['terminals'] * 0.3)     # more endpoints = more open = easier
        composite[letter] = round(score, 2)

    sorted_comp = sorted(composite.items(), key=lambda x: -x[1])

    print(f"{'Rank':>4} {'Letter':>6} {'Score':>7} {'Palette':>8}")
    print("-" * 30)
    for rank, (letter, score) in enumerate(sorted_comp, 1):
        is_pal = "YES" if letter in NULL_PALETTE else ""
        print(f"{rank:>4} {letter:>6} {score:>7.2f} {is_pal:>8}")

    # Test: are palette letters enriched in the top half?
    top_half = set(l for l, s in sorted_comp[:13])
    pal_in_top = len(NULL_PALETTE & top_half)
    pal_in_bottom = len(NULL_PALETTE) - pal_in_top
    nonpal_in_top = 13 - pal_in_top
    nonpal_in_bottom = 13 - pal_in_bottom
    OR, p = fisher_exact_2x2(pal_in_top, pal_in_bottom, nonpal_in_top, nonpal_in_bottom)
    print(f"\nPalette in top half: {pal_in_top}/7, bottom half: {pal_in_bottom}/7")
    print(f"Fisher exact test (top vs bottom enrichment): OR={OR:.2f}, p={p:.4f}")

    results['composite_scores'] = composite
    results['composite_fisher'] = {'OR': OR, 'p': p, 'pal_in_top': pal_in_top}

    # ── 7. Summary ─────────────────────────────────────────────────────────
    print()
    print("=" * 78)
    print("7. SUMMARY")
    print("=" * 78)

    # Count significant features
    sig_mw = sum(1 for k, v in stat_results.items() if k.startswith('mw_') and v.get('p', 1) < 0.05)
    sig_pb = sum(1 for k, v in pb_results.items() if v.get('p', 1) < 0.05)
    sig_fisher = sum(1 for k, v in fisher_results.items() if v.get('p', 1) < 0.05)

    total_tests = len([k for k in stat_results if k.startswith('mw_')]) + len(pb_results) + len(fisher_results)
    total_sig = sig_mw + sig_pb + sig_fisher

    print(f"\nSignificant results (p < 0.05):")
    print(f"  Mann-Whitney U (positions): {sig_mw}/{len([k for k in stat_results if k.startswith('mw_')])}")
    print(f"  Point-biserial (positions): {sig_pb}/{len(pb_results)}")
    print(f"  Fisher exact (letters): {sig_fisher}/{len(fisher_results)}")
    print(f"  Total: {total_sig}/{total_tests}")

    # Bonferroni correction
    bonf_threshold = 0.05 / total_tests
    sig_bonf = 0
    for k, v in stat_results.items():
        if k.startswith('mw_') and v.get('p', 1) < bonf_threshold:
            sig_bonf += 1
    for k, v in pb_results.items():
        if v.get('p', 1) < bonf_threshold:
            sig_bonf += 1
    for k, v in fisher_results.items():
        if v.get('p', 1) < bonf_threshold:
            sig_bonf += 1

    print(f"\n  Bonferroni-corrected (threshold={bonf_threshold:.4f}): {sig_bonf}/{total_tests}")

    projection_p = results['projection_test']['mann_whitney_p']
    print(f"\nProjection model (palette vs non-palette critical angle): p={projection_p:.4f}")
    if projection_p < 0.05:
        print("  --> SIGNIFICANT: Palette letters DO cluster at lower critical angles")
    else:
        print("  --> NOT significant: No evidence palette letters are harder to project")

    mc_p = results['monte_carlo_control']['p_palette_le_7']
    print(f"\nMonte Carlo: P(random 17-mask has palette <= 7 letters) = {mc_p:.6f}")
    if mc_p < 0.001:
        print("  --> The small palette IS unusual, but this was already known (p=0.000024)")
        print("     The question is WHETHER the geometric explanation fits better than")
        print("     the algebraic (KA mod 5) explanation already discovered.")

    # VERDICT
    print("\n" + "=" * 78)
    verdict_lines = []
    if total_sig == 0:
        verdict = "DISPROVED"
        verdict_lines.append("NO geometric features show significant correlation with null status.")
        verdict_lines.append("The letter shape / shadow projection hypothesis does NOT explain the null palette.")
        verdict_lines.append("The algebraic structure (KA mod 5, KRYPTOS x SEVEN grid) remains the better explanation.")
    elif sig_bonf == 0 and total_sig > 0:
        verdict = "INCONCLUSIVE"
        verdict_lines.append(f"{total_sig} nominally significant results, but NONE survive Bonferroni correction.")
        verdict_lines.append("Likely false positives from multiple testing.")
    else:
        verdict = "PROMISING"
        verdict_lines.append(f"{sig_bonf} result(s) survive Bonferroni correction -- warrants further investigation.")

    print(f"VERDICT: {verdict}")
    for line in verdict_lines:
        print(f"  {line}")
    print("=" * 78)

    results['verdict'] = verdict
    results['verdict_details'] = verdict_lines
    results['significant_count'] = {'uncorrected': total_sig, 'bonferroni': sig_bonf, 'total_tests': total_tests}

    # Save results
    out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'letter_shape_null_correlation.json')
    out_path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to: {out_path}")

    return results


if __name__ == '__main__':
    run_analysis()
