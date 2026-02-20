# Session 27: Multiple Linear Regression Meta-Analysis (E-S-132)

**Date**: 2026-02-19
**Method**: OLS multiple linear regression across 129 experiments (10 SA/underdetermination artifacts excluded), 37 active features, crib_matches as DV.

---

## Key Numbers

| Metric | Value |
|--------|-------|
| R-squared | 0.5775 |
| Adj R-squared | 0.4057 |
| RMSE | 2.73 |
| Experiments | 129 (10 excluded) |
| Mean score | 5.88/24 |
| Score entropy | 2.65 bits |

---

## Statistically Significant Features (p < 0.05)

| Feature | Coef | p-value | Direction |
|---------|------|---------|-----------|
| algebraic_elim | -2.68 | 0.001 | Drives score DOWN (decisive eliminations) |
| width_7 | -4.12 | 0.002 | Drives score DOWN (constrained, good discriminator) |
| has_transposition | -3.28 | 0.003 | Drives score DOWN (constraining) |
| monoalpha | -8.70 | 0.007 | Drives score DOWN (instantly eliminated) |
| multi_layer | +3.40 | 0.009 | Drives score UP (more DOF = higher noise floor) |
| gronsfeld | -7.13 | 0.017 | Drives score DOWN (instantly eliminated) |
| thematic_key | -2.03 | 0.017 | Drives score DOWN (sculpture keys = noise) |
| columnar | +3.36 | 0.017 | Drives score UP (more DOF in search) |
| grille | +4.21 | 0.019 | Drives score UP (huge search space = noise ceiling) |
| mixed_alpha | -3.43 | 0.021 | Drives score DOWN (constrained) |
| amsco | +6.76 | 0.029 | Drives score UP (single high-scoring artifact) |
| max_period | -0.05 | 0.035 | Larger periods = slightly lower (counter-intuitive) |

---

## Entropy Findings

| Measure | Entropy (bits) | Max | Ratio |
|---------|---------------|-----|-------|
| K4 CT letter distribution | 4.555 | 4.700 | 0.969 |
| Vigenere keystream (24 crib values) | 3.657 | 4.700 | 0.778 |
| Beaufort keystream (24 crib values) | 3.320 | 4.700 | 0.706 |
| Score distribution across experiments | 2.650 | 3.907 | 0.678 |

**CT entropy is near-maximal** (96.9% of log2(26)) — consistent with well-mixed polyalphabetic cipher. The Beaufort keystream has LOWER entropy than Vigenere (0.706 vs 0.778), suggesting Beaufort produces a slightly more structured key — but neither is close to maximum, confirming the key is non-random and structured.

---

## What the Regression ACTUALLY Tells Us

### The "positive coefficient" features inflate scores through DOF, not signal:
- **multi_layer** (+3.40): More layers = more parameters = more ways to fit noise
- **grille** (+4.21): Huge search space (~2^50) means MC sampling finds high outliers
- **amsco** (+6.76): Single experiment (15/24) that is itself a known artifact
- **uses_sa** and **uses_quadgrams**: SA reliably achieves higher scores by optimization artifact

### The "negative coefficient" features are genuinely constraining:
- **algebraic_elim** (-2.68): Mathematical proofs drive score to 0 — they work
- **width_7** (-4.12): Width-7 columnar is the most constraining transposition tested
- **monoalpha** (-8.70): Monoalphabetic constraints are so tight they instantly eliminate
- **thematic_key** (-2.03): Sculpture-derived keys consistently produce noise

---

## DEFINITIVE STOP LIST (well-eliminated, no further testing needed)

| Strategy | Evidence | Verdict |
|----------|----------|---------|
| Monoalphabetic + transposition | coef=-8.70, 0 survivors | DEAD |
| Gronsfeld + transposition | coef=-7.13, 0 survivors | DEAD |
| Width-7 + periodic key (any period) | 0/15,120 across all orderings | DEAD |
| Mixed keyword alphabets + w7 | coef=-3.43, 0/370K | DEAD |
| Myszkowski + periodic sub | coef=-4.02, 0/47K | DEAD |
| Thematic/sculpture-derived keys | coef=-2.03, 37 exps, mean=6.0 | DEAD |
| Hill + any structured transposition | FP rate ~10^-25 | DEAD |
| Trifid 3x3x3 (all periods) | algebraic proof | DEAD |
| Bifid 6x6 (all periods) | algebraic proof | DEAD |
| Porta + any transposition | 0 survivors via constraint prop | DEAD |
| Progressive K0-K3 key derivation | 12 exps, mean=6.0, coef=+0.66 (NS) | DEAD |
| Autokey (all forms) | coef=-1.21, 8 exps, algebraic proof | DEAD |

## CONTINUE/RECONSIDER LIST

| Strategy | Reason | Action |
|----------|--------|--------|
| Running key from UNKNOWN text | coef=+1.44, but bigram test says key NOT English | Monitor only |
| Non-standard cipher structures | 0 experiments, Tier 4 | Open research |
| Coding charts / physical method | Cannot be tested computationally | Wait for info |
| Position-dependent alphabets | Low coverage, "change the language base" hint | Worth exploring |

---

## The Fundamental Message

**R-squared = 0.578** means cipher strategy choice explains ~58% of score variance. The other 42% comes from:
1. **Search space size** (log_configs has positive but non-significant effect)
2. **SA optimization artifacts** (excluded from regression but dominate high-scorers)
3. **Underdetermination** (97! DOF in arbitrary transposition swamps all scoring)

The score distribution is dominated by the mode at 6/24 (62 experiments = 48%). This IS the noise floor. Everything clustering there confirms the underdetermination wall — no cipher strategy can distinguish itself from random using only 24 cribs.

**Bottom line**: The regression confirms what 26 sessions of experiments already showed — all testable classical cipher families produce noise. The solution either requires information we don't have (coding charts, K5, Smithsonian archive) or a cipher structure we haven't conceived.

---

*Artifact: `artifacts/e_s_132_regression.json` | Script: `scripts/e_s_132_regression_meta_analysis.py`*
*Repro: `PYTHONPATH=src python3 -u scripts/e_s_132_regression_meta_analysis.py`*
