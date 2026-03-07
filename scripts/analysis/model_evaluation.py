#!/usr/bin/env python3
"""
Statistical evaluation of the K4 model using multiple linear regression
and Bayesian analysis. Checks for over/underfitting and computes R².

Generates:
1. Null distributions (random decryptions scored through our pipeline)
2. Multiple linear regression: score ~ features
3. Bayesian model comparison: P(model | observed data)
4. Overfitting diagnostics (cross-validation, AIC/BIC)
"""

import sys
import json
import random
import math
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import numpy as np

from kryptos.kernel.constants import CT, ALPH_IDX, ALPH, CT_LEN
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

random.seed(42)
np.random.seed(42)

N = CT_LEN
ct_nums = np.array([ALPH_IDX[c] for c in CT])

# ── 1. Generate Null Distributions ────────────────────────────────────────

print("=" * 70)
print("PHASE 1: NULL DISTRIBUTIONS")
print("=" * 70)

N_SAMPLES = 5000

def random_text(length=97):
    return ''.join(random.choice(ALPH) for _ in range(length))

def vig_decrypt(ct, key_nums):
    return ''.join(ALPH[(c - k) % 26] for c, k in zip(ct, key_nums))

def beau_decrypt(ct, key_nums):
    return ''.join(ALPH[(k - c) % 26] for c, k in zip(ct, key_nums))

def random_key(period):
    base = [random.randint(0, 25) for _ in range(period)]
    return [base[i % period] for i in range(97)]

# Null 1: Pure random text
print("\n[1a] Scoring pure random 97-char texts...")
null_random_scores = []
null_random_free = []
for _ in range(N_SAMPLES):
    pt = random_text()
    sc = score_candidate(pt)
    fsc = score_candidate_free(pt)
    null_random_scores.append(sc.crib_score)
    null_random_free.append(fsc.crib_score)

# Null 2: Random Vigenere decryptions (various periods)
print("[1b] Scoring random Vigenere decryptions...")
null_vig_by_period = defaultdict(list)
for period in [5, 7, 8, 9, 10, 11, 13]:
    for _ in range(N_SAMPLES // 7):
        key = random_key(period)
        pt = vig_decrypt(ct_nums, key)
        sc = score_candidate(pt)
        null_vig_by_period[period].append(sc.crib_score)

# Null 3: Random permutation then random Vig decryption
print("[1c] Scoring random permutation + random Vig...")
null_scrambled = []
for _ in range(N_SAMPLES):
    perm = list(range(97))
    random.shuffle(perm)
    unscr_nums = np.array([ct_nums[perm[i]] for i in range(97)])
    key = random_key(random.choice([7, 8, 9]))
    pt = vig_decrypt(unscr_nums, key)
    fsc = score_candidate_free(pt)
    null_scrambled.append(fsc.crib_score)

print("\n── Null Distribution Summary ──")
for name, scores in [
    ("Pure random text (fixed crib)", null_random_scores),
    ("Pure random text (free crib)", null_random_free),
    ("Random perm + Vig (free crib)", null_scrambled),
]:
    arr = np.array(scores)
    print(f"  {name}:")
    print(f"    mean={arr.mean():.3f}  std={arr.std():.3f}  "
          f"max={arr.max()}  P(>=8)={np.mean(arr >= 8):.5f}  "
          f"P(>=10)={np.mean(arr >= 10):.6f}")

print("\n  Random Vig by period (fixed crib):")
for period in sorted(null_vig_by_period.keys()):
    arr = np.array(null_vig_by_period[period])
    print(f"    period={period:2d}: mean={arr.mean():.2f}  std={arr.std():.2f}  "
          f"max={arr.max():2d}  P(>=8)={np.mean(arr >= 8):.5f}")


# ── 2. Multiple Linear Regression ────────────────────────────────────────

print("\n" + "=" * 70)
print("PHASE 2: MULTIPLE LINEAR REGRESSION")
print("=" * 70)
print("\nModel: crib_score ~ period + is_beaufort + is_scrambled + bean_pass + IC")
print("Generating structured sample data across model parameter space...\n")

# Generate structured experiment data with known features
X_rows = []
y_scores = []
feature_names = ["period", "is_beaufort", "is_vb", "is_scrambled", "bean_eq_pass", "ic_value"]

def bean_eq_check(key_nums, period):
    """Check if key[27 % period] == key[65 % period]."""
    return key_nums[27 % period] == key_nums[65 % period]

N_REG = 3000
print(f"Generating {N_REG} structured experiments...")

for _ in range(N_REG):
    period = random.choice([5, 7, 8, 9, 10, 11, 13, 16])
    is_beau = random.choice([0, 1])
    is_vb = 0 if is_beau else random.choice([0, 1])
    is_scrambled = random.choice([0, 1])

    base_key = [random.randint(0, 25) for _ in range(period)]
    key = [base_key[i % period] for i in range(97)]
    bean_pass = 1 if bean_eq_check(base_key, period) else 0

    if is_scrambled:
        perm = list(range(97))
        random.shuffle(perm)
        working_ct = np.array([ct_nums[perm[i]] for i in range(97)])
    else:
        working_ct = ct_nums

    if is_beau:
        pt = beau_decrypt(working_ct, key)
    elif is_vb:
        pt = ''.join(ALPH[(c + k) % 26] for c, k in zip(working_ct, key))
    else:
        pt = vig_decrypt(working_ct, key)

    sc = score_candidate(pt)
    if is_scrambled:
        fsc = score_candidate_free(pt)
        score = max(sc.crib_score, fsc.crib_score)
    else:
        score = sc.crib_score

    ic = sc.ic_value
    X_rows.append([period, is_beau, is_vb, is_scrambled, bean_pass, ic])
    y_scores.append(score)

X = np.array(X_rows)
y = np.array(y_scores, dtype=float)

# Add intercept
X_with_intercept = np.column_stack([np.ones(len(X)), X])
all_names = ["intercept"] + feature_names

# OLS regression: beta = (X'X)^-1 X'y
try:
    XtX = X_with_intercept.T @ X_with_intercept
    XtX_inv = np.linalg.inv(XtX)
    beta = XtX_inv @ (X_with_intercept.T @ y)

    y_pred = X_with_intercept @ beta
    residuals = y - y_pred

    SS_res = np.sum(residuals ** 2)
    SS_tot = np.sum((y - np.mean(y)) ** 2)
    R2 = 1 - SS_res / SS_tot

    n, p = X_with_intercept.shape
    R2_adj = 1 - (1 - R2) * (n - 1) / (n - p - 1)

    # Standard errors
    MSE = SS_res / (n - p)
    se_beta = np.sqrt(np.diag(XtX_inv) * MSE)
    t_stats = beta / se_beta

    # AIC / BIC
    log_likelihood = -n / 2 * (np.log(2 * np.pi * MSE) + 1)
    AIC = 2 * p - 2 * log_likelihood
    BIC = p * np.log(n) - 2 * log_likelihood

    print(f"\n── OLS Regression Results (n={n}) ──")
    print(f"{'Feature':20s} {'Coeff':>10s} {'Std Err':>10s} {'t-stat':>10s} {'Signif':>8s}")
    print("-" * 62)
    for i, name in enumerate(all_names):
        sig = "***" if abs(t_stats[i]) > 3.29 else \
              "**" if abs(t_stats[i]) > 2.58 else \
              "*" if abs(t_stats[i]) > 1.96 else ""
        print(f"{name:20s} {beta[i]:10.4f} {se_beta[i]:10.4f} {t_stats[i]:10.3f} {sig:>8s}")

    print(f"\n  R²          = {R2:.6f}")
    print(f"  Adjusted R² = {R2_adj:.6f}")
    print(f"  MSE         = {MSE:.4f}")
    print(f"  AIC         = {AIC:.1f}")
    print(f"  BIC         = {BIC:.1f}")
    print(f"  F-statistic = {(SS_tot - SS_res) / (p - 1) / MSE:.4f}")

    # Interpretation
    print(f"\n── Interpretation ──")
    if R2 < 0.05:
        print("  R² < 0.05: Our model features explain almost NONE of the score variance.")
        print("  This means scores are essentially random with respect to our features.")
        print("  The model is UNDERFITTED — our features don't capture what matters.")
    elif R2 < 0.20:
        print("  R² < 0.20: Weak explanatory power. Features explain some variance")
        print("  but the model is still largely noise-dominated.")
    elif R2 > 0.80:
        print("  R² > 0.80: Strong fit — but check for OVERFITTING (see cross-validation).")

except np.linalg.LinAlgError:
    print("  Matrix inversion failed (singular). Features may be collinear.")


# ── 3. Cross-Validation (Overfitting Check) ──────────────────────────────

print("\n" + "=" * 70)
print("PHASE 3: CROSS-VALIDATION (OVERFITTING CHECK)")
print("=" * 70)

K_FOLDS = 10
fold_size = n // K_FOLDS
cv_r2_scores = []

indices = np.arange(n)
np.random.shuffle(indices)

for fold in range(K_FOLDS):
    test_idx = indices[fold * fold_size:(fold + 1) * fold_size]
    train_idx = np.concatenate([indices[:fold * fold_size], indices[(fold + 1) * fold_size:]])

    X_train = X_with_intercept[train_idx]
    y_train = y[train_idx]
    X_test = X_with_intercept[test_idx]
    y_test = y[test_idx]

    try:
        beta_cv = np.linalg.inv(X_train.T @ X_train) @ (X_train.T @ y_train)
        y_pred_cv = X_test @ beta_cv
        ss_res_cv = np.sum((y_test - y_pred_cv) ** 2)
        ss_tot_cv = np.sum((y_test - np.mean(y_test)) ** 2)
        r2_cv = 1 - ss_res_cv / ss_tot_cv if ss_tot_cv > 0 else 0
        cv_r2_scores.append(r2_cv)
    except np.linalg.LinAlgError:
        cv_r2_scores.append(0)

cv_arr = np.array(cv_r2_scores)
print(f"\n  {K_FOLDS}-Fold CV R² scores: {[f'{x:.4f}' for x in cv_arr]}")
print(f"  Mean CV R²:  {cv_arr.mean():.6f}")
print(f"  Std CV R²:   {cv_arr.std():.6f}")
print(f"  Train R²:    {R2:.6f}")
print(f"  Overfit gap:  {R2 - cv_arr.mean():.6f}")

if R2 - cv_arr.mean() > 0.1:
    print("  WARNING: Large overfit gap (>0.1). Model may be overfitting.")
elif R2 - cv_arr.mean() < 0.02:
    print("  OK: Minimal overfit gap. Model generalizes consistently.")


# ── 4. Bayesian Model Comparison ─────────────────────────────────────────

print("\n" + "=" * 70)
print("PHASE 4: BAYESIAN MODEL COMPARISON")
print("=" * 70)
print("\nComparing hypotheses about K4's true method:")
print("  H_null:      K4 is random / unsolvable with our approach")
print("  H_direct:    Direct paradigm (carved text = real CT)")
print("  H_scrambled: Scrambled paradigm (carved text = permuted CT)")
print("  H_grille:    Grille-based unscrambling + substitution")

# Observed evidence: our BEST scores across all experiments
# From exhaustion_log and our tests today
BEST_DIRECT = 9       # Best score under direct paradigm (600+ experiments)
BEST_SCRAMBLED = 4    # Best score under scrambled paradigm
BEST_GRILLE = 4       # Best grille-based score
N_DIRECT_EXPS = 600   # Approximate number of direct experiments
N_SCRAMBLED_EXPS = 50  # Approximate scrambled experiments
N_GRILLE_EXPS = 20    # Grille-based experiments

print(f"\nObserved evidence:")
print(f"  Direct paradigm:    best={BEST_DIRECT}/24 across ~{N_DIRECT_EXPS} experiments")
print(f"  Scrambled paradigm: best={BEST_SCRAMBLED}/24 across ~{N_SCRAMBLED_EXPS} experiments")
print(f"  Grille-based:       best={BEST_GRILLE}/24 across ~{N_GRILLE_EXPS} experiments")

# Compute P(best_score >= observed | H) using null distributions

# Under H_null: scores follow the null random distribution
null_arr = np.array(null_random_scores)
# P(seeing best=9 in 600 trials from null dist)
p_single_9 = np.mean(null_arr >= 9)
p_best_9_in_600 = 1 - (1 - p_single_9) ** N_DIRECT_EXPS if p_single_9 > 0 else 0

# For free crib (scrambled)
null_free = np.array(null_random_free)
p_single_4_free = np.mean(null_free >= 4)
p_best_4_in_50 = 1 - (1 - p_single_4_free) ** N_SCRAMBLED_EXPS if p_single_4_free > 0 else 0

print(f"\n── Likelihood Computation ──")
print(f"  P(single random score >= 9, fixed crib) = {p_single_9:.6f}")
print(f"  P(best >= 9 in {N_DIRECT_EXPS} trials | H_null) = {p_best_9_in_600:.6f}")
print(f"  P(single random score >= 4, free crib)  = {p_single_4_free:.6f}")
print(f"  P(best >= 4 in {N_SCRAMBLED_EXPS} trials | H_null)  = {p_best_4_in_50:.6f}")

# Bayesian update
# Priors (informed by domain knowledge)
priors = {
    'H_null':      0.10,  # K4 fundamentally unsolvable by us
    'H_direct':    0.15,  # Direct paradigm (mostly eliminated)
    'H_scrambled': 0.35,  # Scrambled paradigm (working hypothesis)
    'H_grille':    0.30,  # Grille-based (best physical lead)
    'H_other':     0.10,  # Something we haven't conceived
}

# Likelihoods: P(observed best scores | hypothesis is TRUE)
# If hypothesis is TRUE, we'd expect HIGHER scores as we search
# The fact that we see only noise-level scores is EVIDENCE AGAINST
# each hypothesis (except H_null and H_other)

# Under H_direct (true): P(best=9 in 600 exps) — if the method is direct,
# 600 experiments should have found scores > 9. Low likelihood.
# Estimate: if direct were true and we've tested ~70% of direct space,
# P(not finding it) ≈ 0.30
likelihoods = {
    'H_null':      0.95,   # Null predicts exactly what we see: all noise
    'H_direct':    0.05,   # 600 exps, exhaustive coverage → should've found it
    'H_scrambled': 0.40,   # Smaller search, paradigm may be right but search incomplete
    'H_grille':    0.50,   # Few experiments, construction unknown → plausible we missed it
    'H_other':     0.70,   # If method is truly novel, our tests are irrelevant
}

# Posterior: P(H | data) ∝ P(data | H) × P(H)
unnormalized = {h: likelihoods[h] * priors[h] for h in priors}
Z = sum(unnormalized.values())
posteriors = {h: v / Z for h, v in unnormalized.items()}

print(f"\n── Bayesian Model Comparison ──")
print(f"{'Hypothesis':20s} {'Prior':>8s} {'Likelihood':>12s} {'Posterior':>10s} {'BF vs null':>12s}")
print("-" * 65)
for h in priors:
    bf = (posteriors[h] / posteriors['H_null']) if posteriors['H_null'] > 0 else float('inf')
    print(f"{h:20s} {priors[h]:8.2f} {likelihoods[h]:12.4f} {posteriors[h]:10.4f} {bf:12.3f}")

# Bayes Factor interpretation
print(f"\n── Bayes Factor Interpretation ──")
print(f"  BF < 1:   Evidence AGAINST hypothesis (vs null)")
print(f"  BF 1-3:   Anecdotal evidence")
print(f"  BF 3-10:  Moderate evidence")
print(f"  BF > 10:  Strong evidence")

winner = max(posteriors, key=posteriors.get)
print(f"\n  Most probable model: {winner} (P={posteriors[winner]:.4f})")


# ── 5. Score Distribution Analysis ───────────────────────────────────────

print("\n" + "=" * 70)
print("PHASE 5: SCORE DISTRIBUTION ANALYSIS")
print("=" * 70)

# Under the null, what's the expected max score for N trials?
print("\n── Expected Maximum Scores ──")
for n_trials in [50, 100, 500, 600, 1000, 5000, 10000]:
    # Simulate max score over n_trials from null distribution
    max_scores = []
    for _ in range(1000):
        sample = np.random.choice(null_arr, size=min(n_trials, len(null_arr)), replace=True)
        max_scores.append(sample.max())
    max_arr = np.array(max_scores)
    print(f"  {n_trials:6d} trials: E[max]={max_arr.mean():.2f}  "
          f"P(max>=9)={np.mean(max_arr >= 9):.4f}  "
          f"P(max>=12)={np.mean(max_arr >= 12):.6f}  "
          f"P(max>=18)={np.mean(max_arr >= 18):.8f}")

# Key question: is our best score of 9 surprising?
print(f"\n── Is our best score (9/24 in ~600 direct experiments) surprising? ──")
max_in_600 = []
for _ in range(10000):
    sample = np.random.choice(null_arr, size=600, replace=True)
    max_in_600.append(sample.max())
max_600_arr = np.array(max_in_600)
p_9_or_better = np.mean(max_600_arr >= 9)
expected_max = max_600_arr.mean()
print(f"  Expected max in 600 null trials: {expected_max:.2f}")
print(f"  P(max >= 9 | null, 600 trials): {p_9_or_better:.4f}")
if p_9_or_better > 0.5:
    print(f"  CONCLUSION: A best score of 9 is EXPECTED under the null.")
    print(f"  Our 600 experiments have NOT found anything above noise.")
elif p_9_or_better > 0.05:
    print(f"  CONCLUSION: Score of 9 is somewhat unlikely but not significant.")
else:
    print(f"  CONCLUSION: Score of 9 would be surprising — worth investigating.")


# ── 6. Model Fitness Summary ─────────────────────────────────────────────

print("\n" + "=" * 70)
print("PHASE 6: MODEL FITNESS SUMMARY")
print("=" * 70)

print(f"""
┌──────────────────────────────────────────────────────────────────┐
│                    MODEL EVALUATION REPORT                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Linear Regression (score ~ features):                           │
│    R²           = {R2:.6f}                                       │
│    Adjusted R²  = {R2_adj:.6f}                                   │
│    CV R² (mean) = {cv_arr.mean():.6f}                                       │
│    Overfit gap  = {R2 - cv_arr.mean():.6f}                                       │
│    AIC          = {AIC:.1f}                                         │
│    BIC          = {BIC:.1f}                                         │
│                                                                  │
│  Bayesian Posteriors:                                            │
│    P(null)      = {posteriors['H_null']:.4f}                                         │
│    P(direct)    = {posteriors['H_direct']:.4f}                                         │
│    P(scrambled) = {posteriors['H_scrambled']:.4f}                                         │
│    P(grille)    = {posteriors['H_grille']:.4f}                                         │
│    P(other)     = {posteriors['H_other']:.4f}                                         │
│                                                                  │
│  Null Distribution:                                              │
│    E[max in 600 trials] = {expected_max:.2f}                                │
│    P(best>=9 | null)    = {p_9_or_better:.4f}                                │
│                                                                  │
│  Diagnosis:                                                      │
│    Underfitting: {'YES' if R2 < 0.05 else 'NO':4s} (R² indicates features ≈ irrelevant)    │
│    Overfitting:  {'YES' if R2 - cv_arr.mean() > 0.1 else 'NO':4s} (CV gap indicates generalization)     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
""")

# Final statistical verdict
print("── STATISTICAL VERDICT ──")
print()
if R2 < 0.05:
    print("1. UNDERFITTING CONFIRMED: Our model features (period, cipher type,")
    print("   alphabet, Bean constraint, scrambling) explain essentially ZERO")
    print("   variance in scores. This means either:")
    print("   a) The true method uses features we haven't modeled, OR")
    print("   b) We haven't tested the right region of parameter space, OR")
    print("   c) The scoring function itself doesn't discriminate the true method.")
    print()

if p_9_or_better > 0.3:
    print("2. NO SIGNAL DETECTED: Our best score of 9/24 across 600+ experiments")
    print("   is EXPECTED under the null hypothesis. We have found exactly what")
    print("   random noise would produce. Zero statistical evidence for any method.")
    print()

print("3. BAYESIAN RANKING:")
for i, (h, p) in enumerate(sorted(posteriors.items(), key=lambda x: -x[1]), 1):
    status = "← favored" if i == 1 else ""
    print(f"   {i}. {h:20s} P={p:.4f} {status}")
print()

if posteriors['H_null'] > 0.3:
    print("4. WARNING: The null hypothesis (unsolvable by our approach) has")
    print(f"   substantial posterior mass ({posteriors['H_null']:.1%}). Our experiments")
    print("   are more consistent with 'no signal' than with any specific method.")
    print("   However, this does NOT mean K4 is unsolvable — only that our")
    print("   current feature space and search strategy haven't found it.")
