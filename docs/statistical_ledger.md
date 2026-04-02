# Statistical Ledger — Anomaly Accounting

**Purpose:** Track every positive anomaly claim with its null model, correction status,
and allowed public wording. Created 2026-04-01 as part of audit remediation.

**Policy:** No anomaly may be cited in public copy without referencing its entry here.
Raw p-values must always be labeled "uncorrected" unless a correction is documented.

---

## Search Breadth Context

| Metric | Value | Source |
|--------|-------|--------|
| Total experiments in exhaustion log | 947 | `exhaustion_log.json` |
| Total result JSON files | 318 | `results/*.json` |
| Approximate independent sub-hypotheses | ~2000-5000 | Estimated from parameter sweeps within experiments |
| Conservative Bonferroni divisor | 1000 | Lower bound on independent tests |

**Implication:** A raw p-value must be < 5 × 10⁻⁵ to survive a conservative
Bonferroni correction at α = 0.05. Only the palette diversity anomaly (p ≈ 2.4 × 10⁻⁵)
approaches this threshold. The BCL enrichment (p = 6.3 × 10⁻⁴) does NOT survive.

---

## Anomaly Registry

### A1: Palette Diversity (7 distinct letters in 17 positions)

| Field | Value |
|-------|-------|
| **Description** | CT letters at 17 consensus null positions use only 7 distinct values {B,G,I,K,O,W,Z} |
| **Discovery method** | Data-discovered (SA optimization identified null positions, then letter diversity measured) |
| **Pre-specified?** | No |
| **Null model 1** | Positional: draw 17 positions from K4's actual 97-position letter distribution, count distinct |
| **P-value (null 1)** | p ≈ 2.4 × 10⁻⁵ (MC, 2M trials, seed=42) |
| **Null model 2** | Uniform: draw 17 letters uniformly from 26-letter alphabet, count distinct |
| **P-value (null 2)** | p ≈ 7.9 × 10⁻⁵ (MC, 2M trials, seed=12345) |
| **Null model 3** | Stirling analytical (uniform alphabet) |
| **P-value (null 3)** | p = 7.78 × 10⁻⁵ (exact) |
| **Canonical p-value** | **p ≈ 2.4 × 10⁻⁵** (positional null — most appropriate) |
| **Dependence caveats** | Palette defined by the same data used to test it; SA process may prefer certain letter sets |
| **Mitigating evidence** | 0/40K SA-optimized masks achieve ≤7 distinct at any score tier; shuffled-CT test (0/500 achieve ≤7) |
| **Corrected status** | Borderline after conservative Bonferroni (1000 tests → corrected p ≈ 0.024). Survives at α=0.05 but not at α=0.01 |
| **Allowed public wording** | "Under one cipher model, candidate filler positions use only 7 of 26 letters (uncorrected p ≈ 1/42,000 under positional null; borderline after correction for search breadth)" |
| **Level** | C (descriptive anomaly) |

### A2: BCL Beaufort Keystream Palette Enrichment (7/8)

| Field | Value |
|-------|-------|
| **Description** | Beaufort A=0 keystream at BCL positions 63-70 has 7/8 palette letters |
| **Discovery method** | Data-discovered (computed after palette was identified) |
| **Pre-specified?** | No (dependent on A1 palette definition) |
| **Null model** | Binomial: each position independently draws from 26 letters; P(in palette) = 7/26 |
| **P-value** | p = 0.000627 (binomial exact; MC confirmed at 0.000616) |
| **Dependence caveats** | Uses the same palette as A1; not independent of A1. Beaufort-specific (Vigenère gives 4/8, p=0.142) |
| **Corrected status** | Does NOT survive Bonferroni correction (1000 × 0.000627 = 0.627). NOT significant after correction |
| **Fisher combination with A1** | Fisher combined p ≈ 3.5 × 10⁻⁷, but tests are NOT independent (share palette definition). Joint MC (10M trials) gave 0 co-occurrences → p < 10⁻⁷ for joint event. However, joint MC does not account for search breadth leading to testing this specific combination |
| **Allowed public wording** | "Under the Beaufort A=0 convention, 7 of 8 keystream values at BCL positions 63-70 are palette letters (uncorrected p = 0.0006; does not survive correction for search breadth)" |
| **Level** | C (descriptive anomaly) |

### A3: KA Mod-5 Column Structure

| Field | Value |
|-------|-------|
| **Description** | All 7 palette letters fall in columns 0 and 3 of a 5-wide KA grid |
| **Discovery method** | Data-discovered |
| **Pre-specified?** | No |
| **Null model** | Hypergeometric: P(7 random letters all in 11-letter superset from C(26,7)) |
| **P-value** | p = C(11,7)/C(26,7) = 0.000502 |
| **Corrected status** | Does NOT survive Bonferroni (1000 × 0.000502 = 0.502) |
| **Allowed public wording** | "The 7 palette letters all fall in two columns of a 5-wide keyword-mixed grid (uncorrected p ≈ 1/2000)" |
| **Level** | C (descriptive anomaly) |

### A4: Stehle Constant-Difference Pattern (positions 55-63)

| Field | Value |
|-------|-------|
| **Description** | Every 4th character in positions 55-63 differs by exactly 5 mod 26 |
| **Discovery method** | Data-discovered (exhaustive search of all spacing/difference combinations) |
| **Pre-specified?** | No |
| **Null model** | Uniform: probability of 5 consecutive lag-4 differences all equal, corrected for 712 tests |
| **P-value** | p ≈ 1/642 (Bonferroni-corrected for 712 spacing×difference tests) |
| **Corrected status** | ALREADY Bonferroni-corrected within its own search space. Additional correction for the ~1000 experiments is NOT applied (would give p ≈ 1.56) |
| **Allowed public wording** | "A constant-difference pattern at positions 55-63 (corrected for 712 tests within that search, p ≈ 1/642)" |
| **Level** | C (descriptive anomaly) |

### A5: KRYPTOS × SEVEN Mod-35 Classification Table

| Field | Value |
|-------|-------|
| **Description** | A (pos%7, pos%5) lookup table perfectly classifies all 35 palette positions as null/real |
| **Discovery method** | Post-hoc search |
| **Pre-specified?** | No |
| **In-sample accuracy** | 35/35 (100%) |
| **LOO-CV accuracy** | 47% (below 49% baseline) |
| **Null calibration** | **COMPLETED (2026-04-01):** 100% of random 17/35 labelings achieve perfect separation under SOME mod pair with product ≤97 (500K trials). The specific pair (7,5) achieves 0/500K (p<2e-6), but this is irrelevant — the search was over ALL pairs, not pre-specified to (7,5). Perfect separation by some mod pair is EXPECTED, not unusual. |
| **Corrected status** | NOT validated. Zero predictive power under cross-validation |
| **Allowed public wording** | "A post-hoc lookup table that fits all positions in-sample but has zero predictive power under cross-validation. Not evidence of a mechanism" |
| **Level** | D (hypothesis/lead — effectively demoted to exploratory due to LOO-CV failure) |

---

## Summary Table

| ID | Anomaly | Raw p | Corrected? | Survives? | Level |
|----|---------|-------|-----------|-----------|-------|
| A1 | Palette diversity | 2.4 × 10⁻⁵ | Bonferroni ÷1000 → 0.024 | Borderline (α=0.05 yes, α=0.01 no) | C |
| A2 | BCL 7/8 palette | 6.3 × 10⁻⁴ | Bonferroni ÷1000 → 0.63 | **No** | C |
| A3 | KA mod-5 columns | 5.0 × 10⁻⁴ | Bonferroni ÷1000 → 0.50 | **No** | C |
| A4 | Stehle Δ4=5 | ~1.6 × 10⁻³ (corrected for 712) | Pre-corrected within search | Borderline for its own search | C |
| A5 | Mod-35 table | N/A (100% of random labelings have SOME perfect mod-pair) | LOO-CV = 47%; null calibration: trivially achievable | **No** | D |

**Bottom line:** Only A1 (palette diversity) approaches significance after a conservative
multiple-testing correction. All other anomalies are descriptive observations that do not
survive correction for the project's full search breadth. No anomaly constitutes evidence
for a specific cipher mechanism.

---

---

## Appendix: Crib Score Threshold Calibration

Null distribution from 2M random 97-character texts (2026-04-01):

| Threshold | Score | P(score ≥ threshold) | Percentile |
|-----------|-------|---------------------|------------|
| NOISE_FLOOR | 6 | 2.4 × 10⁻⁴ | 99.976th |
| STORE_THRESHOLD | 10 | < 5 × 10⁻⁷ | >99.99995th |
| SIGNAL_THRESHOLD | 18 | < 5 × 10⁻⁷ | >99.99995th |
| BREAKTHROUGH | 24 | ≈ 2.7 × 10⁻³⁴ (theoretical) | effectively impossible |

- Mean random score: 0.924 (expected: 24/26 = 0.923)
- 99.999th percentile: score = 7

**Assessment:** Thresholds are well-calibrated for random text. NOISE_FLOOR=6 is
conservative (already at the 99.976th percentile of random). STORE_THRESHOLD=10 and
above are effectively impossible under purely random text. However, under a periodic
key model with period > 7, expected scores are substantially higher (see methodology
page table) — the thresholds are not calibrated for those cases.

Script: `scripts/analysis/e_threshold_calibration.py`

---

*Created 2026-04-01. Update when new anomalies are discovered or corrections are refined.*
