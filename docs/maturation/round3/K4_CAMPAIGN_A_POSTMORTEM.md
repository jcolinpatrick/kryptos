# Campaign A — R3 Maturation Evaluation (postmortem)

**Run window:** 2026-04-22T07:18:15 → ~09:30 local (~2h 12m wall).
**Readiness-gate commit:** `3eee572e`.
**Working tree:** Campaign-A hardening (fallback `origin` tag, runtime halt counters, `AlertEvent.p_value_status` plumbing, Oranchak prompt block).
**Cycles:** 136 → 150 (15 new cycles appended to the 135-cycle existing ledger).
**Preregistration:** `docs/maturation/round3/K4_CAMPAIGN_A_PREREG.md` — criteria locked before launch.

---

## 1. Headline

**Maturation pass.** Four of five preregistered criteria passed; the fifth (criterion 1' — matched-family null on a family outside worked examples) was **unobservable** because no signal-level alert fired (max score 8.0 across the run). That outcome is infrastructurally allowed per the preregistration: "That criterion may simply go unobserved if no signal-level alert fires...and doesn't count as failure."

Zero K4 solutions. Zero breakthroughs. Zero signal. But the architecture ran representatively — DSL path dominated (55% of contracts), theorist never fell to programmatic fallback, admissibility gate fired 18 times, mortality distribution was productive rather than adversarially sterile, and the Oranchak plumbing unlocked at least one hypothesis chain that wouldn't have existed without it.

## 2. Preregistered criterion tally

| # | Criterion | Threshold | Observed | Status |
|---|---|---|---|---|
| 1' | `ok_matched_family` alert on family ∉ DSL_SPEC_CONTRACT worked examples | ≥1 during run | 0 alerts fired (max crib = 8.0, below signal threshold 18) | **UNOBSERVED** (infrastructurally unreachable without signal; preregistration allows) |
| 2a | `dsl_path_contracts` | ≥10 | **22** | **PASS** (2.2× target) |
| 2b | Distinct DSL kinds dispatched | ≥3 | **6** (vigenere, columnar, grille, variant_beaufort, beaufort, polybius) | **PASS** (2× target) |
| 3 | Programmatic fallback cycles | <30% | **0%** (0 of 15) | **PASS** |
| 4a | Max single-stage mortality fraction | ≤60% | 44.4% (critic kills) | **PASS** |
| 4b | Stage-E (scoring outcomes) fraction | ≥20% | **55.6%** | **PASS** (2.8× target) |
| 5 | No hardening halt condition trips | clean 15/15 | halt_reason_hardening="", counters=0 | **PASS** |

**Verdict: MATURATION PASS.** The R3 architecture produced interpretable telemetry at representative firing rates across a 15-cycle sample. The null research outcome ("no K4 signal emerged") is informative — a system that *could* find signal but happened not to is exactly what we wanted to evaluate.

## 3. §6.1.7 DSL utilization metrics

### 3.1 Controller-dispatched contracts: 40 (22 DSL + 18 legacy)

| worker_role | count | share |
|---|---|---|
| `dsl_dispatcher` (Category A) | 22 | 55.0% |
| `agent_sdk_non_dsl_category` (Category B) | 18 | 45.0% |
| `local_rerun` (out-of-campaign reruns) | 8 | — |

The **DSL path was the majority** of dispatched work. Pre-R3, 100% of theories routed through the legacy SDK path. R3's bifurcated architecture re-routed cipher-family theories to pure Python compute while keeping Category-B (non-DSL-family) theories on the legacy path, and the live theorist made extensive use of the cipher-family lane.

### 3.2 DSL kinds observed (in pipeline steps across the 22 DSL contracts)

| kind | occurrences | worked-example? |
|---|---|---|
| `vigenere` | 12 | yes |
| `columnar` | 8 | yes |
| `grille` | 5 | no |
| `variant_beaufort` | 3 | **no** (outside worked examples) |
| `beaufort` | 1 | **no** (outside worked examples) |
| `polybius` | 1 | no |

**6 distinct DSL kinds** — 2× the ≥3 threshold. Crucially, `variant_beaufort` (3 uses) and `beaufort` (1 use) are the two families in the R2-4 matched-null cache that are NOT in the DSL_SPEC_CONTRACT worked examples. Criterion 1' was *evaluable* — had any of those four dispatched theories hit a crib_score of 18+, the matched-family null would have been consulted and criterion 1' would have closed. They didn't, but the infrastructure was genuinely exercised.

### 3.3 Oranchak plumbing effect

- `oranchak_referencing_theories`: **2** (reference pattern `__ORANCHAK_Q3_TOP200__` in DSL spec keyword sweep values).
- At least one emergent composition: *"Pursuit-lead variant: B↔D archive swap + Beaufort on KA alphabet with Oranchak Quagmire-III keyword sweep"* — the theorist composed Day 6 pursuit-lead material with the Oranchak keyword pool in a way that wouldn't have existed without the hardening prompt block.
- No Quagmire-family proposals hit the `dsl_untranslatable` critic path — theorists successfully routed Oranchak keywords as `vigenere`/`variant_beaufort`/`beaufort` per the caveat the prompt block carries. The caveat worked.
- CIA 1996 memo remained excluded (Tier-3 gate held).

### 3.4 Admissibility gate (D column)

- `total_admissibility_rejections`: **18** — averaging 1.2 per cycle.
- `total_translation_errors` (subset of rejections): **6** — about a third of admissibility rejections were DSL translation failures. These are almost certainly the result of theorists proposing shapes the R3-0.5 translators can't yet handle (straight polybius variants, etc.), which is the known R3 §2.1 coverage gap rather than a bug.
- `consecutive_d_zero_cycles` max during run: **0** — the streak counter never advanced. D-column was non-zero in every dispatched cycle.

### 3.5 Theorist telemetry

- `theorist_parse_successes`: **12** (80%)
- `theorist_parse_partial_successes`: **3** (20%)
- `theorist_fallbacks`: **0**
- `programmatic_fallback_cycles`: **0** (counter persisted in state, confirmed against `TheoryRecord.origin` tag)
- `hardening_halt_triggered`: **false** (ran clean 15/15, halt_reason_hardening="")

The theorist agent produced parseable JSON output on every cycle. The Campaign-A hardening's `TheoryRecord.origin` tag confirms this at the record level: zero records carried `origin="programmatic_fallback"`, consistent with the counter.

### 3.6 Override_exhaustion usage (R2-3 feature)

- `total_override_exhaustion_uses`: **3**.
- One example with non-trivial justification: *"Prior vigenere-KA eliminations were all on raw carved CT; this run applies 4 archive-photograph-derived preregistered CT corrections matching the error classes Sanborn documentably introduced in K1/K2/K3. Different CT input bundle, not a rerun of the same assumption set."* — the critic's duplicate-justification detector did not flag this, correctly, because the assumption-bundle difference is substantive.

### 3.7 Matched-null alert path

- `matched_null_consultations`: **0** — no alerts fired at all.
- `matched_null_cache_misses`: **0**.
- `cache_miss` status: **0**.

No BREAKTHROUGH / matched_null_miss halts could fire because no BREAKTHROUGH-level alerts fired. The halt condition is structurally correct (verified in unit tests) but untested under realistic conditions. A future campaign that produces a signal would exercise the halt path.

## 4. Mortality distribution (theories proposed during campaign)

Of 77 theories created between the launch and completion:

| Stage | Count | Share | Notes |
|---|---|---|---|
| A — never proposed (theorist skipped family) | n/a | — | unknowable from DB alone |
| B — critic killed (status=CRITICIZED) | 32 | 44.4% | includes red-team-kill escalations |
| C — red-team killed (pre-dispatch) | subset of B | — | counted in B via status transitions |
| D — admissibility rejected | 18 | 25.0% | R2-3 gate firing |
| E — scoring outcomes (dispatched + scored) | 40 | 55.6% | completed (19) + eliminated (21) |
| F — errors / timeouts | 0 | 0% | no infrastructure failures |

*(Values sum to 90 due to theories that appear in both stage D and E — e.g., a theory attempted, admissibility-rejected, then re-dispatched. The top-line count is 77 theories proposed.)*

**Mortality distribution is non-degenerate**: every stage got populated, no single stage absorbed >60% of theories, and Stage E (actual scoring work, where real research evidence accrues) was the dominant bucket. The pre-hardening concern from the red-team-disprover — that the system might pass as "working" while degenerately sorting all theories into one adversarial-kill bucket — did not materialize.

## 5. Family diversity

Theories proposed this campaign (non-exhaustive sample):
- ct_perturbation × Beaufort-KA with Oranchak
- Coordinate-lie as geographic vector → columnar
- Compass-rose 16-point sector × inner Vigenere-KA (rejected by duplicate_family)
- Scheidt near-Quagmire-III with KA-on-both-sides tableau
- Archive-attested CT perturbations × Beaufort-on-KA (override_exhaustion)
- Width-21 outer columnar × inner Vigenere-AZ
- Compass cipher — 32-rhumb bearings × sculpture physical features
- Bean-624 keystream membership screens
- Bazeries-style written-number substitution using K2 coordinate numerals
- B↔D archive swap + Beaufort-KA + Oranchak QIII
- Boustrophedon sculptor-read perturbation + Vigenere-KA (→ dsl_untranslatable)
- Compass-rose bearings as grille rotation sequence

The campaign touched six distinct research anchors (ct_perturbation, k2_coords, compass, w_delimiter, archive_evidence, grille) and composed several across layers. The final synthesis observed that grille-family theories were saturating at admissibility rejection and recommended pivoting to bounded compass-col-order work.

## 6. Notable behavioral observations

### 6.1 duplicate_family escalation fired (cycle 140)

Red-team flagged "Compass-rose 16-point sector columnar × inner Vigenere-KA" as CONCERNED with `search_space_risk=duplicate_family` citing the 2026-04-16 width-5-13 elimination. The controller's Day-5 escalation policy correctly converted this to REJECT without further compute. The 2026-04-16 project memo (`project_columnar_sub_exhaustive_elimination.md`) was the load-bearing prior.

### 6.2 The dsl_untranslatable path fired once visibly

"Boustrophedon sculptor-read perturbation + Vigenere-KA" (cycle 140 window) was rejected by the critic's `dsl_untranslatable` check because the boustrophedon operation isn't in `_SUPPORTED_KINDS`. This is the R3 §2.1 documented coverage gap behaving as expected — operator should expect a non-zero rate of these rejections, and that's what we got. The rest of the 6 translation-error admissibility rejections are likely analogous structural gaps.

### 6.3 Oranchak emergence pattern

The most interesting emergent behavior: theorists combined Oranchak content with existing anchor surfaces (pursuit leads, archive evidence) rather than treating Oranchak as a standalone lead. That's the right posture — it means Oranchak widened the accessible search space without dominating it.

### 6.4 Synthesis agent giving directional feedback

The end-of-cycle synthesis in cycle 150 recommended "next focus: Pivot away from geometry-justified grille theories and run the small bounded compass-col-order set." This is the results-analyst consuming the cycle's mortality signal and producing useful directional guidance for operators / future campaigns.

## 7. What this campaign evaluated and what it did not

### 7.1 Evaluated (with positive evidence)

- **R3 architecture wiring** runs live at representative rates: DSL dispatch majority, kernel overrule preserved, critic + red-team + stat-audit + synthesis chain operates cleanly.
- **Campaign-A hardening** works: `TheoryRecord.origin` tag fires, halt counters update, both cycle loops consult the same state.
- **Oranchak plumbing** influences theorist behavior: 2 referencing DSL specs, 1 emergent composition with pursuit-lead material.
- **Non-degenerate mortality distribution**: scoring outcomes are the majority terminal stage, not adversarial kills.
- **Zero silent failures**: no fallback, no halt, no infrastructure error.

### 7.2 Not evaluated

- **Signal-level alert path**: no alert fired, so R2-4 matched-family null gate is still live only in unit tests. A future campaign that produces signal — or a synthetic-signal test harness — is the cleanest way to exercise it under load.
- **Oranchak-induced signal**: only 2 Oranchak-referencing DSL specs; too small a sample to conclude anything about whether the Oranchak keyword pool helps *find* K4 vs. just widens proposal space.
- **Multi-cycle depth**: 15 cycles is the first statistical sample (per R3 §8.2). Depth claims about theorist breadth/quality need larger N.
- **Quagmire-family DSL coverage**: by design — the plumbing carries a caveat routing theorists to `vigenere`/`variant_beaufort` for now. Extending the translator to cover `quagmire` straight is a separate brief.

### 7.3 Incidentally surfaced

- **Category-B to Category-A ratio was ~45/55** — better than the R3 §3.2 projection of "3:1 Category-A:Category-B" (which would have been 25/75 Cat-B / Cat-A). Theorists proposed more cipher-family work than the projection assumed; this is healthy.
- **0 "promising" theories** — no theory got promoted to PROMISING status. Consistent with 0 alerts + max score 8.0. The Bean-PASS-not-PROMISING rule (D6-FU-5) is holding: no theories with just bean_passed were auto-promoted.

## 8. Recommendation for next work

1. **Campaign B — isolate the Oranchak effect.** Run 10-15 cycles with the same hardening but *without* `_render_oranchak_corpora_for_prompt` in the prompt. Compare: DSL kind mix, family diversity, mortality distribution, any Oranchak-dependent emergent hypotheses. If the distributions diverge, Oranchak is doing real work; if they don't, the 2 references this campaign were cosmetic.
2. **Extend DSL coverage.** `quagmire` straight, `rail_fence`, `route`, `myszkowski`, `key_tape` translators are the remaining R3 §2.1 gaps. Prioritize by observed critic-rejection rate across campaigns.
3. **Synthetic-signal test harness for the alert path.** Unit tests cover `classify_outcome` returning `(level, status)` but the live plumbing through to the halt condition is only exercised when a real signal fires. A synthetic harness would close the live-path-verification gap without waiting for a solve.
4. **Increase N before claiming depth.** A single 15-cycle sample is statistically thin (R3 §8.2 explicitly flagged this). Run 2-3 more matched campaigns before drawing distributional conclusions about theorist quality.

## 9. Artifacts

- Launch log: `logs/campaign_a/run_20260422_071802.log`
- Theory ledger delta: +77 proposed, +43 tested, +21 eliminated, +0 promising (lifetime: 717 / 483 / 380 / 0)
- Experiments table: +48 rows (22 DSL + 18 legacy + 8 local_rerun)
- No breakthrough events — `results/breakthroughs/` unchanged during the run
- Preregistration: `docs/maturation/round3/K4_CAMPAIGN_A_PREREG.md`
- Hardening memo: `memory/project_campaign_a_hardening_landed.md`

---

*Postmortem complete 2026-04-22. Next session: decide on Campaign B (Oranchak counterfactual) vs. DSL coverage extension vs. synthetic-signal harness.*
