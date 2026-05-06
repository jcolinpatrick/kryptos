# Methodological-Family Conditional Null — Phase 2.2 Decision Memo

**Status:** PHASE 2.2 v3.0 LANDED 2026-05-06. The earlier v1.0 attempt
(degenerate-by-construction null) and v2.0 attempt (rhetorically-
inconsistent decision memo) were retired after successive red-team
reviews. v3.0 corrects the failures called out by the v2.0 review:
headline aggregation matches Phase 2.1, σ vs z-stat units are
distinguished, ledger numbers are re-queried fresh, manifest scope
note describes v3 behavior, Bernoulli rate test is implemented, the
random_text baseline anchor is included, and the design memo's
Option 2 procedural requirement (per-family Documented Impossibility
sections) is satisfied.

**Calibration script:** `scripts/_infra/calibrate_methodological_null_phase2_2.py` (v2.0; output schema v3)
**Test suite:** `kryptosbot/tests/test_methodological_null_phase2_2.py` (48 tests)
**Manifest:** `null_baselines/methodological_null_phase2_2_manifest.json`
**Per-family distributions:** `results/null_baselines/methodological_null_phase2_2/<family>__v1.jsonl`
**Comparison report:** `results/null_baselines/methodological_null_phase2_2/ledger_comparison.json`

**Predecessor memo:** `docs/methodological_audits/methodological_null_decision_memo.md` (Phase 2.1, 2026-05-04, headline `inconclusive due to insufficient sampling or invalid synthetic model`).
**Design memo:** `docs/methodological_audits/methodological_null_phase2_2_design.md` (2026-05-04; per-family Documented Impossibility sections appended 2026-05-06).

**Sample size:** 10,000 per family × 4 Phase 2.2 families = 40,000 samples. Phase 2.1 results for `k2_coords` and `encoding` (10,000 each) inherited unchanged.

**Git commit:** `9082550` (working tree). **Kernel commit:** `4694094`. **RNG seed:** 42.

---

## Headline answer

**`inconclusive due to insufficient sampling or invalid synthetic model`** — the same answer Phase 2.1 produced on substantially the same numerical situation.

The v3 aggregation rule matches Phase 2.1's: any family with verdict `inconclusive` makes the overall headline `inconclusive`. Four of six families (`k3_continuity`, `archive_evidence`, `key_tape`, `geometry`) fall in that bucket because their `max_ratio` falls below the design memo's 0.80 acceptance threshold. The two Phase 2.1 inheritance families (`k2_coords`, `encoding`) classify programmatically as `yes` via Bonferroni z-test, but their absolute mean elevation is small (delta 1.143 and 0.236 respectively, in raw score units) and the Phase 2.1 commentary already characterized them as likely admissibility-bias rather than cryptographic content.

A v2.0 attempt at this memo declared the headline `yes` via a different aggregation rule that was inconsistent with Phase 2.1's. The red-team correctly called this a post-hoc rule shift; v3 reverts to the Phase 2.1-consistent rule.

---

## Per-family results (current ledger, 2026-05-06)

| Family | Source | n_ledger | ledger_mean | ledger_max | n_24 ledger | n_null | null_mean | null_stdev | null_max | n_24 null | max_ratio | delta_z | Bernoulli p | RT-baseline indistinguishable | Verdict |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| k3_continuity | phase_2_2 | 38 | 2.226 | 24 | 1 | 10,000 | 0.896 | 0.935 | 7 | 0 | 0.29 | 8.79 | 1.13e-2 | yes | inconclusive |
| k2_coords | phase_2_1 | 41 | 2.101 | 6 | 0 | 10,000 | 0.958 | 0.907 | 6 | 0 | 1.00 | 8.07 | 1.0 | yes | yes |
| archive_evidence | phase_2_2 | 101 | 1.874 | 24 | 1 | 10,000 | 0.915 | 0.917 | 5 | 0 | 0.21 | 10.49 | 2.99e-2 | yes | inconclusive |
| key_tape | phase_2_2 | 95 | 1.548 | 24 | 2 | 10,000 | 1.010 | 0.946 | 4 | 0 | 0.17 | 5.55 | **3.94e-4** | yes | inconclusive |
| geometry | phase_2_2 | 90 | 1.236 | 16 | 0 | 10,000 | 1.408 | 1.341 | 6 | 0 | 0.38 | -1.22 | 1.0 | no | inconclusive |
| encoding | phase_2_1 | 327 | 1.173 | 7 | 0 | 10,000 | 0.937 | 0.941 | 6 | 0 | 0.86 | 4.50 | 1.0 | yes | yes |

Notes:

- `n_24 ledger` is the count of ledger entries with `best_score = 24` per family.
- `n_24 null` is the count of synthetic samples with `crib_score = 24`.
- `delta_z` is the Bonferroni z-statistic (`delta / SE`, `SE = null_stdev / sqrt(n_ledger)`). The Bonferroni-corrected one-sided threshold across 6 families is z ≈ 2.64.
- `Bernoulli p` is `P(X >= n_24_ledger | X ~ Binomial(n_ledger, p_upper))` with `p_upper = max(n_24_null / n_null, 3/n_null)` (rule-of-three upper 95% CI when `n_24_null = 0`). Significance threshold under Bonferroni-6 is 0.0083.
- `RT-baseline indistinguishable`: whether the family's null mean and stdev are within 0.10 of `random_text__AZ__n97` (mean 0.924, stdev 0.942, max 7) and the null max is at most baseline+1. Five of six families (all except geometry) are indistinguishable.
- The earlier v2 memo cited `encoding` as n=291, mean=1.139. That was stale Phase 2.1 documentation; the current ledger is n=327, mean=1.173 (reflecting newer entries).

---

## Effect size vs significance: keeping the units honest

The earlier v2 decision memo wrote phrases like "+1.04σ elevation, small magnitude". That phrasing conflated two distinct quantities:

- **Effect size in null-stdev units:** `delta_mean / null_stdev`. For `k2_coords`, this is `1.143 / 0.907 = 1.26`. The narrative dismissal as "small absolute elevation" refers to this quantity — about 1.26 stdev of the null distribution.

- **Bonferroni z-statistic:** `delta_mean / SE`, where `SE = null_stdev / sqrt(n_ledger)`. For `k2_coords`, this is `1.143 / (0.907 / sqrt(41)) = 8.07`. This is the test statistic. At α=0.05/6=0.0083 the threshold is 2.64; 8.07 is overwhelmingly above it.

The v3 ledger comparison reports both. The narrative comments on absolute magnitude refer to the effect size (small in absolute terms relative to the score range 0-24); the verdict logic uses the z-statistic (statistically significant). Both are honest. The v2 memo elided the distinction.

---

## What Phase 2.2 v3 changed in v2

| # | Red-team v2 finding | v3 fix |
|---|---|---|
| 1 | Headline `yes` via aggregation rule inconsistent with Phase 2.1 | v3 codes Phase 2.1's *decision-memo narrative override* into the calibrator: any per-family `inconclusive` (from `max_ratio < 0.80`) propagates to `headline = inconclusive`. Phase 2.1's calibrator code itself produced `headline = yes` mechanically; the Phase 2.1 decision memo manually overrode this in prose. v3 does not "match Phase 2.1's rule" at the code level — Phase 2.1's *coded* rule was any-yes-wins. v3 instead encodes Phase 2.1's *intent* (max_ratio < 0.80 should not promote to yes) as a coded rule. The headline string output happens to match Phase 2.1's published headline; the underlying mechanism is materially different and that should be acknowledged rather than glossed as "consistent". |
| 2 | σ vs z-stat conflation in narrative ("+1.04σ, small magnitude") | Distinct fields `delta_mean_in_null_stdev_units` and `delta_z`; narrative explicit about which is being dismissed |
| 3 | Manifest `phase_2_2_scope_note` was v1.0 description | Updated to describe v2 mechanism-aware behavior |
| 4 | Stale ledger numbers (encoding n=291/1.139) | Re-queried; encoding is n=327/1.173 |
| 5 | Bernoulli rate test deferred to "Phase 2.3" | Implemented in v3; per-family Bernoulli p-values in ledger_comparison output |
| 6 | Option 2 closure claimed without "Family X Documented Impossibility" sections in design memo | Sections appended to design memo 2026-05-06 |
| 7 | v2 nulls match random_text baseline (substantive limitation not flagged) | Per-family `vs_random_text_baseline` field; explicit `indistinguishable` flag; flagged in headline narrative |
| 8 | Tests don't enforce subtler invariants | Added `test_geometry_search_cap_is_pinned`, `test_bernoulli_p_value_helper`, `test_inconclusive_in_any_family_implies_inconclusive_headline`, schema-version pin |

---

## What this calibration DOES tell us

1. **The Bernoulli rate test gives a clean, quantitative version of the structural-impossibility argument.** For `key_tape` specifically, the ledger's 2 score-24 events in 95 entries against the synthetic null's 0 events in 10K give a one-sided binomial p = 3.94e-4 — significant at Bonferroni-corrected α=0.05/6. The ledger contains family-specific score-24 phenomena that random-parameter mechanism-aware sampling cannot reproduce. For `k3_continuity` (p=1.13e-2) and `archive_evidence` (p=2.99e-2), the rate difference is significant at α=0.05 but not at Bonferroni-6.

   **Circularity caveat:** the ledger's score-24 events that form the test numerator are the *same artifacts* that motivated Phase 2.2's existence (per `current_signal_inventory.md`'s documentation of those entries as overfit-driven). The synthetic null was deliberately built to NOT reproduce them via flawed-admissibility mechanisms. So the Bernoulli p-value is the rephrasing-as-statistic of the original problem ("the ledger has artifacts the synthetic generator does not produce"), not independent corroborating evidence. The number is rigorous; its interpretive weight is bounded by this circularity. A non-circular Bernoulli framing would require either a held-out ledger sample (not available — Phase 2.2 was designed against the full ledger) or a synthetic null that *includes* flawed-admissibility mechanisms (Phase 2.3 work).

   **Multiplicity correction caveat:** the Bonferroni-6 denominator is conservative. Three of six families (`geometry`, `k2_coords`, `encoding`) have `n_ledger_score_24 = 0` and Bernoulli p = 1.0 by construction — they cannot reject any null. A sharper analysis would correct over the three informative families (α = 0.05/3 ≈ 0.0167); `key_tape` p=3.94e-4 still passes that tighter threshold. The choice of Bonferroni-6 follows the design memo's stated multiplicity rule.

2. **Five of six families' v2 synthetic nulls are statistically indistinguishable from the `random_text__AZ__n97` baseline.** Random-keyed cipher decryption of K4 CT, under random keyword/variant/alphabet/perturbation parameters, produces a score distribution functionally identical to random A-Z plaintext under kernel scoring. The "mechanism-aware" parameterization does not move the distribution beyond what random text produces.

   **Two readings of this finding, both honest:**
   - *Sanity-check reading:* the indistinguishability confirms the v3 generators are mechanism-faithful — applying a uniformly-random key under additive Vigenère/Beaufort/VarBeau is mathematically equivalent to producing uniformly-random plaintext, and the calibration shows exactly that. The generators are doing real cipher work, not a degenerate shortcut.
   - *Limitation reading:* the indistinguishability also means the family-specific parameter regimes do not actually move the score distribution beyond a generic baseline — so the calibration cannot distinguish family-specific phenomena from generic random-text behavior at the mean/stdev level.

   Both readings apply. The v2 review correctly flagged the second reading as a missing acknowledgment in earlier memos; the sanity-check reading is also true and worth recording. The exception across both readings is `geometry`, where post-hoc column-order search inflates the mean (1.408 vs baseline 0.924) but not the max (6 vs baseline 7).

3. **Phase 2.1's "invalid synthetic model" reasoning is preserved by v3.** The Phase 2.1 decision memo declared `inconclusive` because four families' max_ratio was below 0.40 (uniform parameter sampling regime). v3 mechanism-aware sampling moves max_ratio to 0.17–0.38 — slightly higher, but still below the 0.80 acceptance threshold. The substantive reason has shifted from "uniform sampling misses parameter regimes" (Phase 2.1) to "mechanism-aware sampling cannot reproduce theorist-flawed admissibility checks" (v3 + Bernoulli evidence). The headline answer is the same.

4. **The four v3 generators run real cipher operations and produce variable score distributions.** Test suite enforces `null_stdev > 0`, `crib_score < 24` in 100-sample runs, breakthrough_rate < 5%, archive_evidence edits at non-crib positions only, key_tape no canonical-PT back-solve.

5. **Phase 2.1 outputs are byte-stable.** `null_baselines/methodological_null_manifest.json` retains its 2026-05-04 mtime. The `test_phase_2_2_does_not_mutate_phase_2_1_manifest` regression enforces this.

6. **The design memo's Option 2 procedural requirement is satisfied.** Per-family "Family X Documented Impossibility" sections were appended to `methodological_null_phase2_2_design.md` on 2026-05-06.

---

## What this calibration DOES NOT tell us

1. **It does not establish K4 has cryptographic signal in any family.** The aggregate `inconclusive` headline reflects the calibration's inability to characterize four families' upper tails, not a positive finding.

2. **It does not establish K4 has no signal in any family.** A family verdict of `inconclusive` is by definition not `no`.

3. **It does not model theorist-flawed admissibility checks directly.** The most rigorous closure for the four target families would model the actual score-24-generating mechanism: a theorist whose admissibility scoring was wrong, whose proposal was caught by the kernel-overrule path, but whose self-reported score was 24. Modeling that would require Phase 2.3 work (e.g., a Bernoulli rate-comparison framework that explicitly counts pre-overrule score-24 events, with a synthetic null that reproduces the flawed-admissibility regime). v3 lays the groundwork by implementing Bernoulli rate testing.

4. **It does not validate the v3 generators against a third independent reviewer.** v1.0 was rejected by the first red-team pass; v2.0 was rejected by the second; v3 is the third iteration and is the final scoped attempt. A third red-team pass on v3 is the next required acceptance step.

5. **It does not prove the framework can solve K4.** Per `k4_campaign_readiness_gate.md`, "a green gate is necessary, not sufficient."

---

## Decision implications for the readiness gate

Phase 2.2 v3 is **complete in the design memo's Option 2 sense**: per-family Documented Impossibility sections exist in the design memo, and each Phase 2.2 family has a recorded verdict from the directive's allowed answer set.

Phase 2.2 v3 does **not** discharge the `Methodological-null Phase 2.1 status` RED check in `k4_campaign_readiness_gate.md`. The gate's strict GREEN promotion criterion ("Phase 2.2 mechanism-aware-generator implementation produces synthetic null max-ratio ≥ 0.80 for every target family") is not met. The honest reasons:

- For `k3_continuity`, `archive_evidence`, `key_tape`: the ledger's score-24 events come from theorist-flawed admissibility checks (not parameter regimes); a faithful mechanism-aware synthetic null cannot reproduce them without itself adopting the flawed check, which is circular.
- For `geometry`: the post-hoc-search element inflates central tendency but not the upper tail at the chosen search depth (50). A Phase 2.3 sweep over search depth could characterize the trade-off but would change what we are sampling rather than how well.

Three operator paths forward (the operator's call):

1. **Leave the gate RED with the v3 reason recorded.** The substantive finding (mechanism-aware sampling cannot reproduce theorist-flawed-admissibility outliers) is durable and worth preserving as the standing methodological state. Phase 2.3 (flawed-admissibility-modeling + extended Bernoulli framework) is the natural follow-up but not yet in scope.

2. **Amend the readiness gate criterion.** Replace "max_ratio ≥ 0.80 for every target family" with "Option 2 acceptance (max_ratio ≥ 0.80 OR documented impossibility) for every target family." This codifies the design memo's actual rule. Requires a separate dated decision document.

3. **Commission Phase 2.3.** Model the theorist-flawed-admissibility mechanism directly. This is the rigorous path to a `no` or `yes` answer for the four target families, but is substantially more work and would re-open the design phase.

The v3 calibrator and decision memo are scoped to satisfy the design memo's Option 2 acceptance procedurally, not to recommend any specific gate-readiness action. That recommendation belongs in a separate document.

---

## Reproducibility

```bash
# Full v3 calibration (10K per family, ~11s wall)
PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null_phase2_2.py --ledger-comparison

# Quick smoke (200 per family, <1s)
PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null_phase2_2.py --quick --ledger-comparison

# Test suite (48 tests, ~1.5s)
PYTHONPATH=.:src python3 -m pytest kryptosbot/tests/test_methodological_null_phase2_2.py -q
```

Outputs:

- `null_baselines/methodological_null_phase2_2_manifest.json` (committed, ~3KB, schema v1)
- `results/null_baselines/methodological_null_phase2_2/<family>__v1.jsonl` (gitignored, ~600KB at 10K samples)
- `results/null_baselines/methodological_null_phase2_2/ledger_comparison.json` (~10KB, schema `methodological_null_phase2_2.ledger_comparison.v3`)

---

## Limitations explicitly acknowledged

1. **The four v3 generators sample from a curated parameter regime.** Other defensible parameter regimes would produce different null distributions. The calibration represents one defensible model per family.

2. **The geometry post-hoc search depth is fixed at 50.** A Phase 2.3 sweep over depth 1, 5, 50, 500, 5000 would characterize how search depth affects the upper-tail inflation. Test suite pins the current value to prevent silent drift.

3. **The key_tape generator does not exercise null-position insertion.** A Phase 2.3 extension could add null-position sampling to model the M3-class theorist proposals.

4. **Bernoulli p-values use the rule-of-three upper 95% CI when synthetic event count is zero.** A Wilson or Clopper-Pearson upper bound would be slightly tighter; the rule-of-three is conservative.

5. **The third red-team review on v3 has not yet completed.** The decision memo records v3 results and limitations; gate-promotion decisions should await the third review.

6. **Phase 2.3 work is named throughout this memo as the rigorous path to definitive verdicts.** The scope is intentionally not specified here. A separate design memo for Phase 2.3 would be needed.

---

## Verdict

**Headline answer (directive's allowed set):** `inconclusive due to insufficient sampling or invalid synthetic model`. Same as Phase 2.1, on substantially the same numerical situation, with the v3 aggregation rule honoring Phase 2.1's reasoning.

**Per-family verdicts:**

- `k3_continuity`: inconclusive (max_ratio 0.29 < 0.80; documented impossibility; Bernoulli p=0.011 indicates ledger 24-rate exceeds null at α=0.05 but not Bonferroni-6).
- `archive_evidence`: inconclusive (max_ratio 0.21 < 0.80; documented impossibility; Bernoulli p=0.030).
- `key_tape`: inconclusive (max_ratio 0.17 < 0.80; documented impossibility; **Bernoulli p=3.94e-4 significant at Bonferroni-6** — strongest quantitative evidence of family-specific upper-tail phenomena).
- `geometry`: inconclusive (max_ratio 0.38 < 0.80; documented impossibility; ledger has 0 score-24 events so Bernoulli is moot).
- `k2_coords`: yes (Phase 2.1 inheritance; small absolute elevation).
- `encoding`: yes (Phase 2.1 inheritance; small absolute elevation).

**Phase 2.2 deliverable status:** complete (Option 2 procedurally satisfied). The calibrator runs real cipher mechanisms, produces variable score distributions, honors non-circularity criteria, includes Bernoulli rate testing, anchors against `random_text__AZ__n97` baseline, and records per-family Documented Impossibility sections in the design memo.

**Operational consequence for the readiness gate:** unchanged from prior memos. The gate's strict criterion (`max_ratio ≥ 0.80` for every target family) is not met; the gate stays RED on this check. Whether to amend the criterion to allow Option 2 closures, leave RED, or commission Phase 2.3 is the operator's call.

---

## Caveats from third red-team review

The third red-team review of v3 returned `verdict_holds_with_caveats` —
v3 ships, with the following honesty corrections recorded inline so a
future researcher reading this memo cold sees them adjacent to the
claims they qualify:

1. **The "v3 reverts to Phase 2.1's aggregation rule" framing is
   imprecise.** Phase 2.1's calibrator code mechanically produces
   `headline = yes` on Phase 2.1's data via an any-yes-wins rule; the
   Phase 2.1 *decision memo* manually overrode this in narrative prose
   to produce the published `inconclusive` headline. v3 codes that
   narrative override into the calibrator (a per-family `inconclusive`
   from `max_ratio < 0.80`, plus an any-inconclusive-wins rollup). The
   resulting headline string matches Phase 2.1's published headline by
   design, but the underlying mechanism is materially different. The
   v3 fix-table row for finding #1 has been updated to reflect this.

2. **The Bernoulli p=3.94e-4 for key_tape is the
   rephrasing-as-statistic of the original problem.** The ledger's
   score-24 events (the test numerator) are the same artifacts that
   motivated Phase 2.2's existence; the synthetic null was deliberately
   built to NOT reproduce them; the resulting p-value confirms that
   the synthetic null does not reproduce them. Quantitatively rigorous
   but interpretively bounded by the circularity. A non-circular
   Bernoulli framing requires either a held-out ledger sample or a
   synthetic null that includes flawed-admissibility mechanisms — both
   are Phase 2.3 work.

3. **The "5-of-6 indistinguishable from random_text" finding has two
   honest readings:** (a) sanity-check that the v3 generators are
   mechanism-faithful (random key → random PT is mathematical
   property), and (b) substantive limitation that the family-specific
   parameter regimes do not move the distribution beyond a generic
   baseline. The earlier v2 memo missed (b); the v3 memo earlier
   missed (a). Both apply; the "What this calibration DOES tell us"
   section now records both.

4. **The Documented Impossibility sections in the design memo satisfy
   the procedural Option 2 requirement, but the substantive content
   is one argument applied four times.** The geometry section is
   structurally different from the other three (no ledger score-24
   events to reproduce; max_ratio fails for a different reason). The
   memo's "procedurally satisfied" qualifier is honest about this.
   A reviewer skeptical of Option 2's procedural test should note
   that what was written satisfies the design memo's stated rule
   without producing four independent impossibility arguments.

These caveats do not change the verdict (`inconclusive`), the gate
posture (RED, not promoted), or the deliverable status (Option 2
procedurally complete). They record the residual interpretive bounds
honestly.

---

*Authored 2026-05-06 by Claude Opus 4.7. v3 follows two prior red-team
rejections (v1.0: degenerate non-null; v2.0: rhetorical inconsistency
in headline aggregation, σ vs z-stat conflation, stale ledger numbers,
missing design-memo Option 2 sections) and one acceptance with caveats
(v3 final review, this memo). The v3 calibrator is the same code as v2
with three additions: manifest scope note correction, Bernoulli rate
test, random_text baseline cross-comparison. The v3 decision memo
replaces v2's narrative with: Phase 2.1-consistent aggregation
(coded), distinct effect-size vs significance reporting, current
ledger numbers, two-reading framing for random_text indistinguishability,
explicit Bernoulli circularity caveat. Per the user's directive, this
is the final iteration; v4 is not authorized.*
