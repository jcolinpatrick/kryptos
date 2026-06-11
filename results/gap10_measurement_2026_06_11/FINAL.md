# FINAL — GAP-10 crib-bound positional mechanism measurement

- **Campaign:** `e_gap10_01_positional_measurement`
- **Prereg:** `docs/campaigns/gap10_positional_measurement_2026_06_11.md` (frozen before null generation)
- **Verdict:** `MEASURED_NULL` (all frozen primary thresholds; zero evidence candidates)
- **Date:** 2026-06-11 · Git HEAD at run: 41699e2
- Repro: `PYTHONPATH=src venv/bin/python3 -u scripts/statistical/e_gap10_01_positional_measurement.py` (seed 20260611)

## Component 1 — Bean residue-class structure, periods 2-26 [INTERNAL RESULT]

- Claim tested: some period's first-order Bean obstruction count C(p) is
  anomalous vs counterfactual constraint systems.
- Null: CT letters at the 24 crib positions resampled (N1a composition-
  preserving permutation, primary; N1b IID uniform, secondary), Bean
  inequality set RE-DERIVED per draw (`derive_bean_constraints`), M = 10,000
  each. Affine-orbit trap avoided by construction (no within-624 null).
- Result: **no period survives Holm (alpha 0.01).** Smallest per-period
  two-sided tail: p=13 at 0.0178 uncorrected (Holm ≈ 0.44). Joint
  min-tail p = 0.107 (N1a), 0.071 (N1b). Observed first-order survivor
  count 0; null mean 0.099 — unremarkable. Observed |ineq| = 242 vs null
  mean ≈ 246 (informational; global counts are GAP-03 territory).
- Conclusion (H1-conditional): the cribs' residue geometry shows no
  detectable preference or anti-preference for any period 2-26 beyond what
  their letter composition forces.

## Component 2 — gap-region IC, composition-conditional permutation null [INTERNAL RESULT]

- Null: 100,000 uniform same-size position-subsets of the 97 CT letters per
  region; two-sided tails; Holm over 4 regions.
- Result: **no region rejects.** R1 pre-ENE (0-20): IC 0.0667 vs null
  0.0361 ± 0.0123, p = 0.049 uncorrected → Holm ≈ 0.20 (the known E-FRAC-19
  anomaly, again non-significant under a properly corrected null — now also
  under the composition-conditional version). R2 gap (34-62): p = 0.94
  (dead flat). R3 post-BC: p = 0.81. R4 union-73: p = 0.083.
- Conclusion: the gap regions' letter composition is unremarkable given the
  CT's overall composition; the corroboration surface shows nothing for any
  positional-mechanism hypothesis to corroborate.

## Component 3 — cross-boundary change tests [INTERNAL RESULT]

- Statistic: unigram total-variation distance between w-flanks at crib
  boundaries {21, 34, 63, 74}; rank among all valid centers + joint
  mean-rank vs 100,000 placebo 4-subsets. Primary w=10; secondary w ∈ {7,14}.
- Result: **nothing.** w=10 boundary ranks 0.46 / 0.91 / 0.46 / 0.77;
  joint p = 0.58. Secondary windows equally flat (joint 0.59 / 0.83).
- Declared power caveat holds: this rules out detectable unigram change at
  these scales, not mechanism change per se.

## Program verdict and register impact

All three doctrine-specified GAP-10 measurements (REAL_K4_CURRENT_POSITION
§8) are now executed with matched nulls, declared multiplicity, and frozen
thresholds: **zero evidence candidates.** GAP-10 remains OPEN (these
statistics do not exhaust positional structure), but its status moves from
"unowned / unmeasured" to "measured, no signal at the specified statistics".
The corroboration surface (gap regions) is flat, which raises the bar for
any future crib-fitting claim: a proposed positional mechanism now has to
explain why these calibrated measurements saw nothing.

Multiplicity note (declared in prereg): 25 + 4 + 4 primary tests across 3
components; the cross-component minimum (component-1 joint 0.071-0.107)
carries an additional factor-3 burden for any headline use — nothing
approaches threshold either way.
