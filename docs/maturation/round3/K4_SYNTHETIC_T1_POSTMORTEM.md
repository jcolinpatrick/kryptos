# Synthetic Signal Calibration — T1 (SERPENTINE) postmortem

**Run window:** 2026-04-25T20:08:03Z to 2026-04-26T02:08:48Z (6h 00m 45s wall time).
**Preregistration:** `docs/maturation/round3/SYNTHETIC_SIGNAL_CALIBRATION_SPEC.md` (criteria locked before launch).
**Synthetic mechanism:** Quagmire III on KRYPTOS-mixed alphabet, indicator='K', period_keyword='SERPENTINE'.
**Synthetic CT:** `DZFTVZIVQQQVYCFTAQQIFVBCIFCJWZLMAAIAIBJVXVBCSQIRXFPMYGWQCAWZLFFEVQUTFQWJDPHXNBWLDJXDFPVDZVRPAMITD`.
**Run DB:** `db/synth_t1_serpentine_20260425_200803.sqlite`.
**Sentinel:** `db/synth_t1_serpentine_20260425_200803.synthetic_mode.json`.
**Log:** `logs/synth_signal/t1_serpentine_20260425_200803.log`.
**Bundle manifest:** `synth_signal/t1_serpentine/manifest.json`.

---

## 1. Headline

**T1 outcome: FAIL.** No SIGNAL-level alert fired across all 30 cycles. Best score reached was 12/24, in the project's "interesting" band (10-17) and well below the SIGNAL threshold of 18. The architecture had a clean, well-instrumented run with healthy mortality distribution and zero infrastructure issues, and produced a clear architectural finding: **the theorist's hypothesis generation curates thematic keyword lists from puzzle vocabulary rather than enumerating thematic_v2 systematically, and SERPENTINE never made any of the curated lists across 16 dispatched Quagmire-family experiments.**

The spec's §1.1 PASS criterion required SIGNAL by cycle 30. The spec's FAIL criterion is no SIGNAL by cycle 60, with one extension allowed if cycle 30 showed non-trivial parameter exploration in progress. Cycle 30 completed cleanly without signal; the architectural finding is structural rather than progress-related, so an extension would not be expected to change the outcome. This postmortem accepts the outcome as FAIL without the cycle-60 extension. The decision is recorded as such; spec §1.1 permits the extension; declining to take it is operator-discretion under the preregistration.

---

## 2. Preregistered criterion tally

| Criterion (spec §1.1) | Threshold | Observed | Status |
|---|---|---|---|
| SIGNAL alert fires | crib >= 18 AND bean_passed AND ngram_per_char >= -4.0 AND p_value <= 1e-6, by cycle 30 | best score 12, no SIGNAL alert, no PASS conditions met | **FAIL** |
| Mortality distribution non-degenerate | no single stage absorbs >60% of theories | scoring stage 50.7%, eliminated stage 70.2% of tested, no stage absorbed >70% | PASS (architecture is firing correctly) |
| Theorist parse rate | fallback rate < 20% of cycles | 0 fallbacks in 30 cycles (0%) | PASS |
| Halt counters | clean run, no hardening halt | halt_reason_hardening='', consecutive_fallback_cycles=0, consecutive_d_zero_cycles=0 | PASS |
| Infrastructure failures | none | 0 errors, 0 timeouts, no DB corruption, sentinel preserved | PASS |

The PASS columns above are about *architecture health*, not about T1's calibration outcome. The architecture ran exactly as designed; what failed is the calibration's primary criterion, which is what the calibration was meant to test.

---

## 3. Architecture metrics

### 3.1 Coverage

| metric | T1 value | Campaign A reference | Notes |
|---|---|---|---|
| Cycles completed | 30 | 15 | T1 was preregistered for 30 |
| Theories proposed | 147 | 77 | ~5/cycle in both, T1 rate matches |
| Theories tested | 104 | 40 | T1 exposed broader test surface |
| Theories eliminated | 73 | 21 | |
| Theories promising | 0 | 0 | matches Campaign A |
| dsl_dispatcher contracts | 59 | 22 | T1 ratio: 56.7% (A: 55%) |
| agent_sdk_non_dsl_category | 45 | 18 | T1 ratio: 43.3% (A: 45%) |
| Distinct DSL kinds dispatched | 10 | 6 | **broader than Campaign A** |
| Theorist parse successes | 27 | 12 | |
| Theorist parse partial | 3 | 3 | |
| Theorist fallbacks | 0 | 0 | both clean |
| Halt counters | all 0 | all 0 | both clean |
| Wall time | 6h 00m | ~2h 12m | T1 took 30 cycles vs A's 15 |

### 3.2 DSL kinds dispatched (in pipeline steps across 59 dsl_dispatcher experiments)

| kind | T1 occurrences | Campaign A | Campaign B |
|---|---|---|---|
| vigenere | 34 | 12 | (not separately tracked) |
| route | 24 | 0 | (B-DSL-expanded, 0 used) |
| **quagmire** | **16** | 0 | 4 |
| myszkowski | 8 | 0 | (B-DSL-expanded, 0 used) |
| rail_fence | 7 | 0 | (B-DSL-expanded, 0 used) |
| beaufort | 7 | 1 | |
| columnar | 5 | 8 | |
| variant_beaufort | 3 | 3 | |
| grille | 2 | 5 | |
| atbash | 1 | 0 | |

T1's DSL coverage is the broadest seen on any preregistered campaign so far. The R3-0.5 translator additions (route, rail_fence, myszkowski, quagmire) all got non-zero usage, validating the post-Campaign-B prompt fix that landed the kind="route" coverage gap. Quagmire dispatches in particular jumped from 4 (Campaign B) to 16 (T1), showing that the synthetic CT *is* nudging the theorist toward the right cipher family.

### 3.3 Score distribution

| score band | count | share of scored |
|---|---|---|
| 0 (no crib match) | 44 | 41.5% |
| 1-3 | 46 | 43.4% |
| 4-5 (low noise) | 9 | 8.5% |
| 6-9 (typical noise band) | 5 | 4.7% |
| 10-17 (interesting band) | **2** | 1.9% |
| 18-23 (SIGNAL) | 0 | 0% |
| 24 (BREAKTHROUGH) | 0 | 0% |

The two interesting-band hits are the calibration's most important data points outside the SERPENTINE coverage gap. They are:

| score | hypothesis | mechanism dispatched |
|---|---|---|
| 12 | AAA serpentine copper screen read + Vigenere(KA): primary archive anchor | route(serpentine, 14x7) → vigenere(KA, keywords: KRYPTOS, PALIMPSEST, ABSCISSA, IQLUSION, SCHEIDT, SANBORN, TABLEAUX, SERPENTINE, ...) |
| 10 | Mirror-KA Quagmire IV with reverse-KA indicator alphabet | quagmire(KA, variant=quagmire_iv, indicator in {K,S,A,R}, keywords: BERLIN, CLOCK, SHADOW, LIGHT, ABSENCE, NUANCE, ILLUSION, ...) |

Both are *near-miss in shape, miss in substance*. The 12-point hit added a pre-cipher serpentine route transposition and used Vigenere on KA (which is mathematically Quagmire II with KRYPTOS as the CT alphabet, *not* Quagmire III which uses KRYPTOS for both alphabets). The 10-point hit used Quagmire IV with a reverse-KA pt-alphabet, which is again not the synthetic mechanism. Their scores are consistent with crib-character coincidence under wrong cipher families, not with partial recovery of the synthetic mechanism.

---

## 4. Diagnostic finding: SERPENTINE keyword coverage gap

This is the calibration's central architectural finding. It is more specific than "the architecture didn't find signal."

**SERPENTINE was tested as a Quagmire III period_keyword zero times across all 30 cycles, despite Quagmire III being dispatched 16 times.** SERPENTINE appears in 22 experiment configurations, but in every case it appears as either:

- a transposition route variant (`"variant": "serpentine"` for `kind="route"`), or
- a Vigenere keyword in a multi-layer route+vigenere pipeline (the score-12 hypothesis), or
- text inside a hypothesis_id or notes field

It never appears as the literal `period_keyword` value of a Quagmire III pipeline step. The 16 Quagmire dispatches collectively swept these period_keyword values: KRYPTOS, PALIMPSEST, ABSCISSA, SHADOW, ECLIPSE, BERLIN, CLOCK, LIGHT, LAYER, DIGETAL, ABSENCE, NUANCE, ILLUSION, SUBTLE, INVISIBLE, MAGNETIC, EARTH, FIELD, GATHERED, TRANSMITTED, UNDERGROUND, DESPERATELY. Every one is drawn from K1-K3 plaintext words, K1-K3 keywords, or Sanborn-vocabulary references. None is from systematic enumeration of `wordlists/thematic_keywords_v2.txt` (which contains SERPENTINE at slot 213 of 425).

The mechanism is structural to how the theorist composes proposals. When prompted to propose a Quagmire III sweep, it *curates* a keyword list as a creative act drawing on puzzle context. This is exactly the behavior that has produced strong hypothesis discovery on Campaign A/B/C. It is also exactly the behavior that misses corpus enumeration. SERPENTINE was not on any K1-K3 surface, not in Sanborn's quoted vocabulary that the prompt surfaces, and not derived from a numeric structural anchor (like the compass-rose bearings that produced multiple Quagmire III variants). The theorist had no semantic reason to surface it.

---

## 5. Mortality distribution

| stage | count | share | notes |
|---|---|---|---|
| Stage A (never proposed) | unknowable | — | by definition |
| Stage B (critic killed) | 43 | 29.3% of proposed | duplicate-family flags, kill-criteria gaps |
| Stage C (red-team killed) | counted in B | — | red-team rejects pre-dispatch convert to CRITICIZED |
| Stage D (admissibility) | 0-3 cycles observed | small | mostly 0 in steady state |
| Stage E (scoring) | 104 | 70.7% of proposed | non-degenerate, scoring is dominant terminal |
| Stage F (errors / timeouts) | 0 | 0% | no infrastructure failures |

Stage E (scoring) being the dominant terminal stage is the same healthy-distribution signature seen in Campaigns A and B. The architecture is not adversarially-killing or admissibility-rejecting most theories; it is letting them run, score them honestly, and producing meaningful zero-or-near-zero outcomes. The 0.7% theorist-fallback rate (matched against Campaign A) and the absence of halt counters firing both indicate the campaign's failure mode is content-driven, not infrastructure-driven.

---

## 6. Synthesis-agent observations during the run

The end-of-cycle synthesis flagged behavioral patterns at multiple points:

- "Next theorist should propose at most one W-segment theory" appeared in mid-run synthesis. This indicates the theorist was repeatedly proposing W-segment hypotheses despite the 2026-04-20 rotation memo demoting W-segmentation to multi-layer-only. The synthesis's pushback worked, but only retrospectively per cycle. The W-rotation prompt change has propagated into theorist behavior partially, not fully.
- The synthesis correctly identified zero-information cycles when admissibility rejected all dispatched theories, and recommended next-cycle anchor surfaces accordingly.
- The CT-perturbation anchor surface received multiple proposals across cycles, indicating the controller anomaly overhaul (where ct_perturbation was elevated to primary on 2026-04-20) is firing in the prompt as designed.

---

## 7. Spec §4 decision matrix mapping

T1 outcome → row 4 of the decision matrix (FAIL):

> *"Architecture cannot find signal on its own worked example. Strong evidence that more cycles on real K4 won't help. §1 belief is supported with a hard data point. §2/§3 should pivot toward Purpose B explicitly, or toward primary-source disclosure as the only realistic path."*

Per spec §1.2, T2 (DEFECTOR) is gated on T1 PASS. T1 FAILed; **T2 does not run**.

This is the binding interpretation per the preregistration. The strategic doc §1 belief Colin wrote on 2026-04-23 ("either bespoke private cipher or Sanborn made an error he doesn't realize, search won't find it") is now empirically anchored: the architecture did not find signal on a synthetic where the answer was *fully within reach* (in a corpus the prompt nominally surfaces, in a cipher family the architecture knows, with cribs at canonical positions). The failure mode is mechanical and sharply identified: theorist hypothesis curation does not enumerate corpora.

---

## 8. What T1 evaluated and what it did not

### 8.1 Evaluated (with positive evidence)

- **Synthetic-mode infrastructure works.** Kernel CT override propagated to subprocess, sentinel file landed, fresh DB used, no contamination of real-K4 ledgers, kernel `_verify` correctly gated K4-specific assertions, Bean derivation auto-recomputed against the synthetic CT (BEAN_EQ=2, BEAN_INEQ=249, BEAN_LINEAR=80).
- **R3 architecture under realistic load.** 6-hour run, 30 cycles, 147 proposals, 104 dispatches, zero halts, zero fallbacks. Same architecture behaviors as Campaigns A/B/C, sustained across 2x the cycle count.
- **DSL coverage breadth.** 10 distinct DSL kinds dispatched, including all four R3-0.5 expansion translators (route, rail_fence, myszkowski, quagmire). The post-Campaign-B prompt fix demonstrably routes serpentine-class hypotheses to kind="route" rather than to dsl_untranslatable.
- **Theorist hypothesis-class diversity.** Proposals spanned single-layer Quagmire variants, two-layer route+cipher compositions, multi-layer mirror-alphabet variants, archive-anchored CT perturbations, compass-rose physical bearings, coordinate-lie geometric overlays, K3-continuity transposition revivals. Breadth was high.

### 8.2 Not evaluated, by design or by outcome

- **T2 (DEFECTOR) elimination-scoping property.** Gated on T1 PASS per spec; not run.
- **Architecture's ability to find a corpus-enumerable answer.** This is what T1 did evaluate, and the answer is *no* under the current theorist prompt and proposal generation pattern.
- **Architecture's ability to find a non-corpus-enumerable answer.** T1 was not designed to test this; the synthetic answer was specifically chosen to be in a surfaceable corpus to give the architecture its best chance.

### 8.3 Incidentally surfaced

- **Synthesis-agent-flagged W-overproposal.** Even after the 2026-04-20 rotation, the theorist proposed W-segment hypotheses at a rate the synthesis chose to push back on. The rotation has reduced but not eliminated W-themed proposals.
- **Two-layer near-miss pattern.** The score-12 hit was a route-then-vigenere pipeline, not the synthetic answer's single-layer Quagmire III. This suggests the architecture's strong prior toward multi-layer compositions can produce coincidence-driven moderate scores even when a simpler single-layer answer is correct. Worth flagging for future calibration design.

---

## 9. Recommendations for next session

This is operator-prerogative; the recommendations below are options not directives.

1. **Populate strategic doc §2 (Purpose A vs B)** as the primary next move. T1's FAIL is the empirical anchor §1 was waiting for. With it, §2 can be answered honestly. The framework-as-output Purpose B has been substantially validated by today's commits (publish workflow, synthetic-mode infrastructure, README polish, kryptosbot.com sweep) regardless of K4's outcome, and T1 confirmed Purpose A's diminishing return. A formal §2 commitment closes the deferred-loop pattern §4 of the strategic doc named.
2. **Architectural fix: corpus enumeration mode.** The cleanly-identified failure mode in T1 is queueable. A theorist-prompt addition or a separate enumeration runner that says "for any cipher family that gets dispatched, also run the corpus enumeration over the relevant wordlist (thematic_keywords_v2.txt for thematic ciphers) before proposing further creative variants" would close the SERPENTINE-class gap. This would change real-K4 outcomes only if K4's keyword is a thematic_v2 entry not currently in the theorist's curated lists, but the fix is cheap and doesn't depend on that being the case.
3. **CT-perturbation campaign.** The CT-perturbation anchor surface is the controller's currently-elevated primary, and T1 saw three CT-perturbation theories (all at scores 0-3). Running a structured CT-perturbation campaign with archive-derived perturbations (per the AAA evidence and the README's Working Hypothesis #2 framing) would test the most-supported hypothesis class outside synthetic mode.
4. **Decline corpus-enumeration synthetic retest.** A T1' that fixed the corpus-enumeration prompt mode and re-ran would PASS by construction (since SERPENTINE would land in slot 213 of an enumerated thematic_v2 sweep). That'd be a constructed pass, not a calibration. If the architecture is improved, the next calibration should use a different synthetic answer that would also fail under the unfixed prompt.

---

## 10. Cross-cutting observations on framework maturity

T1 ran at the same envelope as Campaigns A, B, and C and produced telemetry that's directly comparable. The fact that T1 ran for 30 cycles rather than 15 without architectural drift, halt-counter trips, or theorist degradation is itself a maturity signal. The kryptosbot architecture has now been characterized across four campaigns of similar shape (A, B, C, T1) with consistent mortality distributions, consistent worker-role splits (~55/45 dsl_dispatcher / agent_sdk), consistent DSL-kind diversity (6-10 distinct), and consistent theorist parse rates (>80% successful). The architecture is reproducibly running at production scale.

What T1 newly contributed beyond previous campaigns:
- Doubled cycle count (30 vs 15) with no observed architectural degradation.
- Confirmed that the synthetic-mode kernel override does not perturb the controller's behavior in any visible way (no theorist anomalies, no scoring anomalies, no halt anomalies). The architecture treats the synthetic CT as if it were real K4, which is what the calibration design required.
- Produced the first mechanically clean failure mode identification: hypothesis curation versus corpus enumeration. This is sharper than any prior campaign's "no signal" outcome.

The infrastructure improvements landed today (synthetic-mode kernel override, build/launch tools, pre-push hook, publish workflow, K4-keywords-must-fit-public-art-context feedback memory) are reusable artifacts that will outlive T1's specific outcome. None of them depend on K4 being solved.

---

## 11. Artifacts

- **Run DB:** `db/synth_t1_serpentine_20260425_200803.sqlite` (1.69 MB).
- **Sentinel:** `db/synth_t1_serpentine_20260425_200803.synthetic_mode.json`.
- **Stdout/err log:** `logs/synth_signal/t1_serpentine_20260425_200803.log`.
- **Bundle manifest:** `synth_signal/t1_serpentine/manifest.json` (synthetic CT, synthetic PT, mechanism config, BEAN counts, round-trip verification).
- **Spec (preregistration):** `docs/maturation/round3/SYNTHETIC_SIGNAL_CALIBRATION_SPEC.md`.
- **Project memo (launch):** `memory/project_synthetic_signal_calibration_launched.md` (in auto-memory store).
- **Postmortem checklist (handoff):** `docs/maturation/round3/K4_SYNTHETIC_T1_POSTMORTEM_CHECKLIST.md`.
- **This postmortem:** `docs/maturation/round3/K4_SYNTHETIC_T1_POSTMORTEM.md`.

---

## 12. Outcome summary (one paragraph for the project's claim record)

T1 of the synthetic-signal calibration ran 30 cycles over 6 hours against a synthetic CT generated by Quagmire III with period_keyword=SERPENTINE on the KRYPTOS-mixed alphabet. The architecture proposed 147 theories, dispatched 104, and scored 0 SIGNAL alerts; best score reached was 12/24 in the interesting band. The synthetic answer's exact configuration was within reach (Quagmire III is supported by the DSL, SERPENTINE is in `wordlists/thematic_keywords_v2.txt` at slot 213, and Quagmire III was dispatched 16 times during the run) but was not proposed, because the theorist's hypothesis-generation pattern curates thematic keyword lists from puzzle vocabulary rather than enumerating corpora. Outcome: FAIL per spec §1.1. The result anchors the strategic doc §1 conclusion empirically: under the current architecture, scale alone does not solve a hard cipher even when the answer is in the proposal space, because the proposal space is creative-rotation-bounded rather than enumeration-bounded. T2 (DEFECTOR) is gated on T1 PASS and therefore does not run.

---

*Postmortem authored 2026-04-26. Spec §3.3 template applied. §4 decision matrix interpretation is binding. Operator decisions on §2 and §3 of the strategic reconsideration are unblocked by this result.*
