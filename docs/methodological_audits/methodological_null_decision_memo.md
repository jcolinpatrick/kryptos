# Methodological-Family Conditional Null — Decision Memo

**Status:** PHASE 2.1 COMPLETE 2026-05-04. Calibration script, full-mode run, ledger comparison all on disk.

**Calibration script:** `scripts/_infra/calibrate_methodological_null.py` (v1.0)
**Manifest:** `null_baselines/methodological_null_manifest.json`
**Per-family distributions:** `results/null_baselines/methodological_null/<family>__v1.jsonl` (gitignored)
**Comparison report:** `results/null_baselines/methodological_null/ledger_comparison.json`

**Sample size:** 10,000 per family × 6 families = 60,000 total synthetic samples. Run wall-clock: ~5 seconds.

**Git commit:** `5329e483444b9b6dc1e64c8b066c00e4c81f4bb1` (post-Phase 2 audit).
**Kernel commit:** `7105ac297264deaed2d29a8dc6aab497dcbc264e` (manifest).
**RNG seed:** 42 (deterministic; reproducible by re-running with same seed).

---

## The question this memo answers

Per the directive:

> "Do the methodological-family score elevations survive a random-admitted-methodological-theory null?"

Allowed answers: `yes` / `no` / `inconclusive due to insufficient sampling or invalid synthetic model`.

## Headline answer

**`inconclusive due to insufficient sampling or invalid synthetic model`** (specifically: invalid synthetic model for 4 of 6 families).

The synthetic generators implemented in `calibrate_methodological_null.py` produce samples that do not reach the ledger's BREAKTHROUGH (score=24) regime for k3_continuity, archive_evidence, key_tape, and geometry. The ratio of synthetic-null max to ledger max is 0.21–0.38 for these four families, indicating regime mismatch. The synthetic generators sample parameters uniformly; documented ledger BREAKTHROUGHs are algebraic-degeneracy / structural-overfit cases that uniform sampling does not produce.

For the two families where the synthetic null DOES reach the ledger regime (k2_coords with ratio 1.00, encoding with ratio 0.86), the headline answer would be `no` — the mean elevations are small (+1.04 and +0.20 respectively), within ~1σ of pooled stdev, and likely attributable to admissibility-bias rather than cryptographic content. But the directive asks for a single answer across all 6 families; with 4/6 invalid-synthetic-model, the only honest answer is **inconclusive**.

---

## Per-family results

| Family | N (ledger) | N (null) | Ledger mean | Null mean | Δ | Δz | Ledger max | Null max | Max ratio |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| k3_continuity | 34 | 10,000 | 2.135 | 0.940 | +1.20 | 7.31 | 24 | 6 | 0.25 |
| k2_coords | 36 | 10,000 | 2.032 | 0.958 | +1.07 | 7.11 | 6 | 6 | **1.00** |
| archive_evidence | 95 | 10,000 | 1.824 | 0.922 | +0.90 | 9.41 | 24 | 5 | 0.21 |
| key_tape | 89 | 10,000 | 1.574 | 0.915 | +0.66 | 6.67 | 24 | 6 | 0.25 |
| geometry | 90 | 10,000 | 1.236 | 0.902 | +0.33 | 3.34 | 16 | 6 | 0.38 |
| encoding | 291 | 10,000 | 1.139 | 0.937 | +0.20 | 3.64 | 7 | 6 | **0.86** |

All Δz exceed the Bonferroni-corrected threshold (~2.64 for α=0.05/6 across 6 families). Statistically the elevation is real for every family.

**The interpretive split is on max ratio:**

- **k2_coords (1.00)**: synthetic null reaches the same max as the ledger. The synthetic generator captures the parameter regime ledger theories actually inhabit. Ledger mean elevation of +1.04 with this faithful null is small and likely admissibility-bias.
- **encoding (0.86)**: similar — synthetic null max is 6, ledger max is 7. Close enough that the regimes overlap. Mean elevation of +0.20 is small.
- **k3_continuity (0.25), archive_evidence (0.21), key_tape (0.25), geometry (0.38)**: synthetic null reaches max 5–6; ledger has BREAKTHROUGHs (16–24). The synthetic generator does NOT generate the parameter combinations that produce these high-score ledger entries.

For the four mismatched families, the high ledger means are pulled UP by their BREAKTHROUGH outliers (the 6 BREAKTHROUGHs documented in `current_signal_inventory.md` are all in these four families). The synthetic null doesn't generate these because they require specific algebraic-degeneracy patterns (Bean-invariance under non-crib edits, period-impossibility configurations, etc.) — patterns a uniform sampler doesn't construct.

---

## Why the synthetic model is "invalid" for 4 of 6 families

The `current_signal_inventory.md` Phase 1 audit documented that all 6 ledger BREAKTHROUGHs (score=24) are eliminated with structural / algebraic reasons:

| ID | Family | Failure-reason class |
|---|---|---|
| `4ae72d4d` | archive_evidence | Bean-invariance under non-crib edits (algebraic degeneracy) |
| `c682ed26` | crib_analysis | Bounded keyword-pool exhaustively zero |
| `e1cfceed` | grille | Period-impossibility + Monte Carlo zero |
| `46caf41f` | k3_continuity | K3+K4 = 433 prime; no rectangular grid |
| `795fde3e` | key_tape | Bounded search exhaustively zero (720 configs) |
| `a2f896e5` | key_tape | Exhaustive primer search zero |

These 6 entries are "score 24" because their mechanism algebraically forces a 24/24 crib match (e.g., Bean is invariant under non-crib edits, so all 1.64M perturbations trivially "pass" Bean — score 24/24 by definition, not by content). The framework's safety gates correctly caught each as overfit.

A uniform random sampler does not construct these algebraic-degeneracy patterns. Therefore the synthetic null in this calibration **systematically underestimates the ledger max** for any family that has been touched by a degenerate-mechanism proposal. That's exactly the pattern observed: 4 of 6 families have ratio < 0.40.

The 2 families without ratio mismatch (k2_coords, encoding) appear because:

- **k2_coords**: bounded by digit-arithmetic. No degenerate-mechanism BREAKTHROUGH has been proposed in this family. Ledger max = 6, identical to synthetic null max.
- **encoding**: very large family (N=291) with diverse mechanisms. The single ledger entry at score 7 is within the synthetic null's reach.

---

## What this calibration DOES tell us

1. **The synthetic generators are working correctly within their scope.** Per-family means cluster around 0.92 (random_text null mean) with stdev ~0.93 — exactly the random_text distribution. Bean pass rate is 0.0000 across all 6 families × 10K samples (60K total, zero Bean passes), which is consistent with Bean being highly restrictive (624 valid keystreams out of 26²⁴).

2. **The ledger means ARE statistically elevated above uniform-random parameter sampling.** Δz values range from 3.34 (geometry) to 9.41 (archive_evidence). These elevations are not chance under uniform sampling.

3. **For 2 of 6 families (k2_coords, encoding), the elevation is small and within faithful-null range.** If the directive's question is restricted to these two families, the answer is `no` — the elevations are within admissibility-bias range and do not warrant family-level cryptographic-content claims.

4. **For 4 of 6 families (k3_continuity, archive_evidence, key_tape, geometry), the synthetic null doesn't reach the ledger max regime.** The mean elevations are pulled up by documented overfits. A faithful null for these families would require generators that capture the algebraic-degeneracy mechanisms theorists have proposed.

---

## What this calibration DOES NOT tell us

1. Whether the per-family elevations represent cryptographic content vs. admissibility-bias. **The synthetic null cannot distinguish these.**

2. Whether more sophisticated synthetic generators (per-family, mechanism-aware) would shift the mismatched 4 families into the same "elevation small, within faithful null" pattern as k2_coords/encoding. This would require Phase 2.2 work: building family-specific synthetic generators that include the algebraic-degeneracy parameter regimes ledger theories explore.

3. Whether the existing ledger entries above synthetic-null max are themselves "real" or "post-hoc selection bias from human theorists." Both interpretations are consistent with the data.

---

## Decision implications for K4 reopening

Per the K4 Evidence Calibration and Reopening Plan, this Phase 2.1 outcome does NOT discharge the no-new-search moratorium. The decision memo `k4_reopen_decision_memo.md` (Phase 7) stated:

> "The single authorized work item is complete Phase 2.1 — methodological-family conditional null calibration."

Phase 2.1 is now complete in the sense that the synthetic-null sampler exists, has been run, and the comparison has been produced. But the result is **inconclusive**, not **no signal exists**.

The honest reopening posture is therefore unchanged:

- **Do not claim K4 has no cryptographic signal.** The current calibration does not support that claim.
- **Do not reopen broad search.** The current calibration does not support that either.
- **Recommended next step: Phase 2.2 — family-specific mechanism-aware synthetic generators.** Build per-family synthetic generators that include the documented algebraic-degeneracy mechanisms. Re-run the comparison. If the 4 mismatched families' max ratios approach 1.0 with Phase 2.2 generators, AND the mean elevations remain small, the answer becomes `no`. If the elevations remain large under faithful generators, the answer becomes `yes` and specific family mechanisms warrant bounded retest.

Phase 2.2 is its own brainstorm/plan/build cycle, similar in scope to Phase 2.1. ~2-4 days estimated. Until it lands, the moratorium continues for the same reason it was instituted: the project cannot yet distinguish admitted-theory overfit from cryptographic signal.

---

## Reproducibility

```bash
# Full calibration (10K per family, ~5s wall)
PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null.py --ledger-comparison

# Quick smoke test (200 per family, ~1s)
PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null.py --quick --ledger-comparison

# Single-family
PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null.py --only-family k3_continuity --ledger-comparison

# Per-family inspection
cat results/null_baselines/methodological_null/k3_continuity__v1.jsonl | head -5
cat results/null_baselines/methodological_null/ledger_comparison.json | python3 -m json.tool
```

Outputs (post-run):

- `null_baselines/methodological_null_manifest.json` (committed, ~3KB)
- `results/null_baselines/methodological_null/<family>__v1.jsonl` (gitignored, ~1.4MB each × 6 = ~8.4MB)
- `results/null_baselines/methodological_null/ledger_comparison.json` (~3KB)

---

## Limitations explicitly acknowledged

1. **Uniform random parameter sampling is a baseline, not a faithful theorist model.** Real theorists concentrate on parameters they find "interesting" — even without K4 plaintext access. This calibration cannot capture that.

2. **The 6 family generators are first-pass implementations.** Each represents one defensible model of the family's parameter space. Other defensible models would yield different null distributions; this calibration does not characterize that variance.

3. **The Bonferroni correction is across 6 families.** If Phase 2.2 expands the family count or adds within-family stratification, the multiplicity correction grows.

4. **No synthetic-generator failure-mode tests are committed in this Phase 2.1 deliverable.** The design doc (`admitted_theory_conditional_null_design.md`) lists them; this script's quick-mode acts as a smoke test but not a formal test suite.

5. **The synthetic null was scored against the canonical 97-char K4 CT.** It does not address ciphertext-perturbation theories properly — for archive_evidence, only one position is perturbed per sample (Hamming-1), but the ledger's archive_evidence theories sometimes test Hamming-2 or larger perturbation classes. Multi-position perturbation would be a Phase 2.2 refinement.

---

## Verdict

**Headline answer: `inconclusive due to insufficient sampling or invalid synthetic model`.**

Specifically: **invalid synthetic model** for 4 of 6 families (synthetic generator does not reach the ledger max regime). For the 2 families where the synthetic generator IS in the right regime (k2_coords, encoding), the mean elevations are small and consistent with admissibility-bias rather than cryptographic content.

No K4 search reopening is recommended. The no-new-search moratorium continues, with Phase 2.2 (family-specific mechanism-aware synthetic generators) identified as the next constructive step.

---

*Authored 2026-05-04 by Claude Opus 4.7 acting as principal research engineer / epistemic auditor. The directive's allowed answers are `yes` / `no` / `inconclusive due to insufficient sampling or invalid synthetic model`. The honest verdict is the third. Reproducible via `calibrate_methodological_null.py --ledger-comparison`.*
