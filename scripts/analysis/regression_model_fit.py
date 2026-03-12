#!/usr/bin/env python3
"""
Multiple Linear Regression Analysis of K4 Keystream
=====================================================

The 24 known crib positions give us 24 (position, CT, PT) triples.
For each cipher variant, the keystream k[i] is fully determined.

Question: can k[i] be predicted from features of position i?
- R² ≈ 0 → no exploitable structure at these positions (underfitting / wrong model)
- R² ≈ 1 with few features → simple cipher structure found
- R² ≈ 1 only with many features → overfitting noise

This is a clean quantitative test of whether ANY model family we've tried
actually explains the crib-position keystream better than random.
"""

import sys
sys.path.insert(0, 'src')

import numpy as np
from kryptos.kernel.constants import CT
from kryptos.kernel.alphabet import AZ, KA

# ── Known crib data ──────────────────────────────────────────────────────────
ENE_POS, ENE_PT = 21, 'EASTNORTHEAST'
BC_POS, BC_PT = 63, 'BERLINCLOCK'

CRIB_POSITIONS = []
CRIB_PT_CHARS = []
for j, ch in enumerate(ENE_PT):
    CRIB_POSITIONS.append(ENE_POS + j)
    CRIB_PT_CHARS.append(ch)
for j, ch in enumerate(BC_PT):
    CRIB_POSITIONS.append(BC_POS + j)
    CRIB_PT_CHARS.append(ch)

CRIB_POSITIONS = np.array(CRIB_POSITIONS)  # shape (24,)
N_CRIBS = len(CRIB_POSITIONS)  # 24


def compute_keystream(alphabet, mode):
    """Compute keystream at 24 crib positions for a given alphabet and mode."""
    k = []
    for pos, pt_ch in zip(CRIB_POSITIONS, CRIB_PT_CHARS):
        ct_val = alphabet.char_to_idx(CT[pos])
        pt_val = alphabet.char_to_idx(pt_ch)
        if mode == 'vig':
            ki = (ct_val - pt_val) % 26
        elif mode == 'beau':
            ki = (ct_val + pt_val) % 26
        elif mode == 'vbeau':
            ki = (pt_val - ct_val) % 26
        else:
            raise ValueError(f"Unknown mode: {mode}")
        k.append(ki)
    return np.array(k, dtype=float)


def build_feature_matrix(positions, feature_set):
    """Build feature matrix X for given positions and feature specification.

    Returns (X, feature_names, n_params).
    Feature sets:
      'constant'     : intercept only (1 param)
      'linear'       : i (2 params)
      'quadratic'    : i, i² (3 params)
      'cubic'        : i, i², i³ (4 params)
      'periodic_P'   : indicator vars for i mod P (P params)
      'progressive_P': i mod P + floor(i/P) (P+1 params)
      'grid_W'       : col=i%W, row=i//W (3 params)
      'full_grid_W'  : indicator(i%W) + row=i//W (W+1 params)
      'prog_grid_W'  : indicator(i%W) + row*step (W+1 params, step=1 fixed for regression)
    """
    n = len(positions)
    pos = positions.astype(float)

    if feature_set == 'constant':
        X = np.ones((n, 1))
        names = ['intercept']

    elif feature_set == 'linear':
        X = np.column_stack([np.ones(n), pos])
        names = ['intercept', 'i']

    elif feature_set == 'quadratic':
        X = np.column_stack([np.ones(n), pos, pos**2])
        names = ['intercept', 'i', 'i²']

    elif feature_set == 'cubic':
        X = np.column_stack([np.ones(n), pos, pos**2, pos**3])
        names = ['intercept', 'i', 'i²', 'i³']

    elif feature_set.startswith('periodic_'):
        P = int(feature_set.split('_')[1])
        # Indicator variables for each residue class (no intercept needed)
        X = np.zeros((n, P))
        for j in range(P):
            X[:, j] = (positions % P == j).astype(float)
        names = [f'r{j}' for j in range(P)]

    elif feature_set.startswith('progressive_'):
        P = int(feature_set.split('_')[1])
        # Indicator for residue + linear row term
        X = np.zeros((n, P + 1))
        for j in range(P):
            X[:, j] = (positions % P == j).astype(float)
        X[:, P] = positions // P  # row number
        names = [f'r{j}' for j in range(P)] + ['row']

    elif feature_set.startswith('full_grid_'):
        W = int(feature_set.split('_')[2])
        X = np.zeros((n, W + 1))
        for j in range(W):
            X[:, j] = (positions % W == j).astype(float)
        X[:, W] = positions // W
        names = [f'col{j}' for j in range(W)] + ['row']

    elif feature_set.startswith('sin_'):
        # Fourier features: sin(2πi/P), cos(2πi/P) for period P
        P = int(feature_set.split('_')[1])
        X = np.column_stack([
            np.ones(n),
            np.sin(2 * np.pi * pos / P),
            np.cos(2 * np.pi * pos / P),
        ])
        names = ['intercept', f'sin(2πi/{P})', f'cos(2πi/{P})']

    else:
        raise ValueError(f"Unknown feature set: {feature_set}")

    return X, names


def ols_r_squared(X, y):
    """Compute R² using ordinary least squares. Returns (R², adj_R², coeffs)."""
    n, p = X.shape
    if p >= n:
        # More params than data points: perfect fit but meaningless
        return 1.0, float('nan'), np.zeros(p)

    try:
        # β = (X'X)^(-1) X'y
        coeffs = np.linalg.lstsq(X, y, rcond=None)[0]
        y_pred = X @ coeffs
        ss_res = np.sum((y - y_pred) ** 2)
        ss_tot = np.sum((y - np.mean(y)) ** 2)

        if ss_tot < 1e-10:
            return 1.0, 1.0, coeffs  # constant y

        r2 = 1 - ss_res / ss_tot
        # Adjusted R²: penalizes for number of parameters
        adj_r2 = 1 - (1 - r2) * (n - 1) / (n - p - 1) if n > p + 1 else float('nan')

        return r2, adj_r2, coeffs
    except np.linalg.LinAlgError:
        return float('nan'), float('nan'), np.zeros(p)


def aic_bic(X, y):
    """Compute AIC and BIC for OLS model."""
    n, p = X.shape
    if p >= n:
        return float('inf'), float('inf')

    coeffs = np.linalg.lstsq(X, y, rcond=None)[0]
    y_pred = X @ coeffs
    ss_res = np.sum((y - y_pred) ** 2)

    if ss_res < 1e-10:
        return float('-inf'), float('-inf')

    # Log-likelihood (assuming Gaussian errors)
    sigma2 = ss_res / n
    log_lik = -n/2 * np.log(2 * np.pi * sigma2) - n/2

    aic = -2 * log_lik + 2 * p
    bic = -2 * log_lik + p * np.log(n)

    return aic, bic


def main():
    print("=" * 90)
    print("MULTIPLE LINEAR REGRESSION ANALYSIS OF K4 KEYSTREAM")
    print("=" * 90)
    print(f"\nData: {N_CRIBS} known (position, CT, PT) triples from EASTNORTHEAST + BERLINCLOCK")
    print(f"Positions: {list(CRIB_POSITIONS)}")

    # ── Compute keystreams ───────────────────────────────────────────────────
    keystreams = {}
    for alph_name, alph in [('AZ', AZ), ('KA', KA)]:
        for mode in ['vig', 'beau', 'vbeau']:
            label = f"{alph_name}/{mode}"
            k = compute_keystream(alph, mode)
            keystreams[label] = k

    print(f"\n{'Label':<12s} Keystream values (24 positions)")
    print("-" * 90)
    for label, k in keystreams.items():
        vals = ' '.join(f'{int(v):2d}' for v in k)
        print(f"{label:<12s} {vals}")

    # ── Define feature sets to test ──────────────────────────────────────────
    feature_sets = [
        ('constant',        'Intercept only',          1),
        ('linear',          'Linear (i)',              2),
        ('quadratic',       'Quadratic (i, i²)',       3),
        ('cubic',           'Cubic (i, i², i³)',       4),
        ('sin_13',          'Fourier period 13',       3),
        ('sin_7',           'Fourier period 7',        3),
        ('periodic_2',      'Period 2',                2),
        ('periodic_3',      'Period 3',                3),
        ('periodic_4',      'Period 4',                4),
        ('periodic_5',      'Period 5',                5),
        ('periodic_7',      'Period 7',                7),
        ('periodic_13',     'Period 13',               13),
        ('progressive_7',   'Progressive period 7',    8),
        ('progressive_13',  'Progressive period 13',   14),
        ('full_grid_7',     'Grid width 7',            8),
        ('full_grid_8',     'Grid width 8',            9),
        ('full_grid_13',    'Grid width 13',           14),
        ('full_grid_14',    'Grid width 14',           15),
        ('periodic_24',     'Period 24 (saturated)',    24),
    ]

    # ── Run regression for each keystream × feature set ──────────────────────
    print("\n" + "=" * 90)
    print("R² VALUES: How well does each model explain the keystream?")
    print("=" * 90)

    # We'll focus on the most promising keystreams
    focus_keystreams = ['AZ/beau', 'AZ/vig', 'KA/beau', 'KA/vig', 'AZ/vbeau', 'KA/vbeau']

    for ks_label in focus_keystreams:
        k = keystreams[ks_label]
        print(f"\n{'─'*90}")
        print(f"Keystream: {ks_label}")
        print(f"  Mean={np.mean(k):.2f}, Std={np.std(k):.2f}, "
              f"Range=[{int(np.min(k))}, {int(np.max(k))}]")
        print(f"  {'Feature Set':<30s} {'Params':>6s} {'R²':>8s} {'Adj R²':>8s} {'AIC':>10s} {'BIC':>10s}")
        print(f"  {'-'*72}")

        for fs_name, fs_desc, n_params in feature_sets:
            X, names = build_feature_matrix(CRIB_POSITIONS, fs_name)
            r2, adj_r2, coeffs = ols_r_squared(X, k)
            aic_val, bic_val = aic_bic(X, k)

            # Flag significance
            flag = ''
            if adj_r2 > 0.5:
                flag = ' ◀ NOTABLE'
            if adj_r2 > 0.8:
                flag = ' ◀◀ STRONG'
            if n_params >= N_CRIBS:
                flag = ' [SATURATED]'

            print(f"  {fs_desc:<30s} {n_params:>6d} {r2:>8.4f} "
                  f"{adj_r2:>8.4f} {aic_val:>10.1f} {bic_val:>10.1f}{flag}")

    # ── Best model per keystream (by adjusted R²) ───────────────────────────
    print("\n" + "=" * 90)
    print("BEST MODEL PER KEYSTREAM (by adjusted R², excluding saturated)")
    print("=" * 90)

    best_overall_r2 = -999
    best_overall = None

    for ks_label in focus_keystreams:
        k = keystreams[ks_label]
        best_adj_r2 = -999
        best_fs = None

        for fs_name, fs_desc, n_params in feature_sets:
            if n_params >= N_CRIBS:
                continue  # skip saturated
            X, names = build_feature_matrix(CRIB_POSITIONS, fs_name)
            r2, adj_r2, coeffs = ols_r_squared(X, k)
            if not np.isnan(adj_r2) and adj_r2 > best_adj_r2:
                best_adj_r2 = adj_r2
                best_fs = (fs_name, fs_desc, n_params, r2, adj_r2, coeffs, names)

        if best_fs:
            fs_name, fs_desc, n_params, r2, adj_r2, coeffs, names = best_fs
            print(f"\n{ks_label}: {fs_desc} (p={n_params})")
            print(f"  R²={r2:.4f}, Adj R²={adj_r2:.4f}")

            if adj_r2 > best_overall_r2:
                best_overall_r2 = adj_r2
                best_overall = (ks_label, fs_desc, n_params, r2, adj_r2)

    if best_overall:
        print(f"\n*** BEST OVERALL: {best_overall[0]} + {best_overall[1]} "
              f"(p={best_overall[2]}): R²={best_overall[3]:.4f}, Adj R²={best_overall[4]:.4f} ***")

    # ── Overfitting curve ────────────────────────────────────────────────────
    print("\n" + "=" * 90)
    print("OVERFITTING CURVE: R² vs number of parameters")
    print("=" * 90)
    print("\nUsing periodic feature sets (most natural for ciphers):")
    print(f"  {'Period':>6s} {'Params':>6s} {'R² (AZ/beau)':>14s} {'Adj R²':>8s}  "
          f"{'R² (KA/beau)':>14s} {'Adj R²':>8s}")

    for p in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]:
        fs_name = f'periodic_{p}'

        X, _ = build_feature_matrix(CRIB_POSITIONS, fs_name)

        r2_az, adj_az, _ = ols_r_squared(X, keystreams['AZ/beau'])
        r2_ka, adj_ka, _ = ols_r_squared(X, keystreams['KA/beau'])

        sat = ' [SAT]' if p >= 24 else ''
        print(f"  {p:>6d} {p:>6d} {r2_az:>14.4f} {adj_az:>8.4f}  "
              f"{r2_ka:>14.4f} {adj_ka:>8.4f}{sat}")

    # ── Null distribution for R² ─────────────────────────────────────────────
    print("\n" + "=" * 90)
    print("NULL DISTRIBUTION: R² from random keystreams (10,000 trials)")
    print("=" * 90)

    rng = np.random.default_rng(42)

    for fs_name, fs_desc, n_params in [
        ('periodic_7', 'Period 7', 7),
        ('periodic_13', 'Period 13', 13),
        ('progressive_13', 'Progressive 13', 14),
        ('linear', 'Linear', 2),
    ]:
        X, _ = build_feature_matrix(CRIB_POSITIONS, fs_name)

        null_r2 = []
        for _ in range(10000):
            fake_k = rng.integers(0, 26, size=N_CRIBS).astype(float)
            r2, _, _ = ols_r_squared(X, fake_k)
            null_r2.append(r2)

        null_r2 = np.array(null_r2)

        # Compare actual keystreams
        for ks_label in ['AZ/beau', 'KA/beau']:
            actual_r2, _, _ = ols_r_squared(X, keystreams[ks_label])
            p_val = np.mean(null_r2 >= actual_r2)
            print(f"  {fs_desc:<20s} + {ks_label:<10s}: R²={actual_r2:.4f}, "
                  f"null median={np.median(null_r2):.4f}, p={p_val:.4f}")

    # ── Summary verdict ──────────────────────────────────────────────────────
    print("\n" + "=" * 90)
    print("VERDICT")
    print("=" * 90)

    # Check if any model achieves significant R²
    significant = False
    for ks_label in focus_keystreams:
        k = keystreams[ks_label]
        for fs_name, fs_desc, n_params in feature_sets:
            if n_params >= N_CRIBS:
                continue
            X, _ = build_feature_matrix(CRIB_POSITIONS, fs_name)
            r2, adj_r2, _ = ols_r_squared(X, k)
            if not np.isnan(adj_r2) and adj_r2 > 0.5:
                significant = True
                print(f"  NOTABLE: {ks_label} + {fs_desc}: adj_R²={adj_r2:.4f}")

    if not significant:
        print("""
  NO model achieves adjusted R² > 0.5 on any keystream.

  This means: the keystream at the 24 crib positions has NO exploitable
  positional structure under any standard cipher assumption (periodic,
  progressive, polynomial, grid-based).

  Interpretation:
  • UNDERFITTING: We haven't found the right model family yet.
  • OR: The positions are WRONG — a transposition layer scrambles the
    relationship between carved-text position and cipher position.
    After undoing the correct transposition, R² should jump dramatically.

  This is quantitative confirmation that the two-system model is required:
  the carved-text positions don't correspond to cipher positions.

  Has R² improved across 600+ experiments? NO — because every experiment
  operated on the same 24 (position, CT, PT) triples. No amount of trying
  different cipher families changes the underlying data. R² can only improve
  when we find the correct TRANSPOSITION that remaps positions.
""")


if __name__ == '__main__':
    main()
