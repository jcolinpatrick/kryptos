# Campaign A — R3 Maturation Evaluation (preregistration)

**Commissioned:** 2026-04-22
**Readiness-gate commit:** `3eee572e` (doctor 20/0, tests/ 1532, kryptosbot/tests/ 805, self-test K1/15 K2/17 K3/9345, R2-5 real-API K1 pass)
**Hardening commit:** (recorded after this doc lands)
**Status:** PREREGISTERED — do not edit success criteria after launch.

---

## 1. Research question

Does the post-maturation theorist → DSL → worker loop (Round 3 as of 2026-04-21) produce *informative* elimination/confirmation evidence? Can the Pantheon propose novel cipher hypotheses and run them via DSL hooks in a way that meaningfully extends the project's elimination frontier, or is the system's productive output primarily adversarial disproof of its own proposals?

This is an **architecture evaluation**, not a K4 solve attempt. Null outcome ("no novel signal emerged in 15 cycles") is informative if the telemetry in §6.1.7 shows the wiring fired representatively.

## 2. Launch configuration

```bash
PYTHONPATH=src python3 -u kryptosbot/run_controller.py --cycles 15 --theories 5
```

- `--cycles 15` per R3 §3.3 recommendation.
- `--theories 5` per R3 §3.3.
- No `--dry-run`, no `--skip-critic`.
- Oranchak reference corpora (wordlists + candidate fills) plumbed into theorist prompt via `_render_oranchak_corpora_for_prompt` (Campaign-A hardening, 2026-04-22).
- CIA 1996 memo deliberately excluded (Tier-3 hearsay).

## 3. Success criteria (preregistered — ALL must hold for "maturation pass")

The red-team-disprover flagged the pre-hardening criteria as "satisfiable by R3 wiring firing at least once while the research question goes unanswered." The strengthened criteria below require **representative firing**.

### Criterion 1' — Matched-family null on a family outside the worked examples

At least one cycle emits an alert with `p_value_status = ok_matched_family` on a theory whose `family` is **NOT** one of the families named in the DSL_SPEC_CONTRACT worked examples (`vigenere`, `columnar_single`, `columnar_double`). Matched families available from R2-4: `{beaufort, variant_beaufort, columnar_single, columnar_double}`. This means the only two non-worked-example targets are `beaufort` and `variant_beaufort`.

**Rationale:** The worked examples lead the theorist toward Vigenere/columnar shapes; a matched-null consultation on those does not test the system's breadth. Requiring a `beaufort` / `variant_beaufort` matched-null hit forces the theorist to exercise the R2-4 matched-null infrastructure on a family it wasn't handed.

### Criterion 2 — D-column fires representatively

`dsl_path_contracts >= 10` **AND** `>= 3` distinct DSL-supported kinds observed in dispatched contracts. DSL-supported kinds per R3-0.5: `{identity, vigenere, beaufort, variant_beaufort, columnar, atbash, procedural, grille, polybius}`.

**Rationale:** A single dispatched Vigenere contract in 75 slots satisfies the naive `dsl_path_contracts > 0` criterion but tells us nothing about whether the DSL is exercised. 10 contracts over ≥3 kinds is a modest but meaningful sample.

### Criterion 3 — Fallback rate stays under operator-intervention threshold

`programmatic_fallback_cycles < 30%` of cycles (per R3 §2.3).

**Hardening note:** The §6.1.7 title-pattern detection is backed by the durable `TheoryRecord.origin` field (Campaign-A hardening). Fallback cycles are now identifiable by record inspection, not title grep. A cycle is "fallback" if any candidate carries `origin="programmatic_fallback"`.

### Criterion 4 — Mortality distribution is non-degenerate AND productive

Two thresholds jointly:
- **Max single-stage fraction ≤ 60%**: no single mortality stage (theorist-never-proposed / critic-rejected / dsl-untranslatable / red-team-killed / dispatcher-rejected / scoring-outcomes / error) absorbs more than 60% of approved theories.
- **Stage-E (scoring outcomes, dispatched) ≥ 20%**: at least 20% of critic-approved theories reach actual worker scoring.

**Rationale:** The red team's strongest objection was that "non-degenerate" was unfalsifiable. Stage-E ≥ 20% directly tests whether the theorist/critic/red-team chain produces theories worth testing, vs. a system that just adversarially disproves everything internally.

### Criterion 5 — No showstopper halt condition trips

The Campaign-A hardening wires three runtime halt conditions in both cycle loops. The run must complete 15 cycles without hitting any of:
- `FALLBACK_HALT_STREAK = 3` consecutive fallback cycles.
- `D_ZERO_HALT_STREAK = 3` consecutive dispatched cycles with zero admissibility rejections.
- Any BREAKTHROUGH alert with `p_value_status ∈ {matched_null_miss, cache_miss}`.

If the run halts under any of these, the operator investigates the cause before re-launching. A halt does NOT count as campaign failure — it counts as the hardening doing its job.

## 4. Halt conditions (auto-enforced by the hardening)

Wired into both `controller.run` and `run_controller.do_run` (per `feedback_dup_cycle_loop_trap`):

1. **Fallback streak (≥3 consecutive cycles)** — theorist agent broken; halt and investigate before committing more compute.
2. **D-zero streak (≥3 consecutive dispatched cycles)** — DSL path not being exercised or all specs trivially admissible; operator review required.
3. **BREAKTHROUGH + matched_null_miss / cache_miss** — null cache unreliable for this family; calibrate via `scripts/_infra/calibrate_null_baselines.py` before treating the alert as signal.
4. **Panic from `_verify_against_kernel`** — never expected; halt immediately (pre-existing behavior).

The halt state persists in `ControllerState.halt_reason_hardening`. Both cycle loops break after persist + synthesis so the halt reason is saved.

## 5. What this campaign does NOT test

- **K4 solvability.** The expected outcome is null; that's informative architecture evidence, not failure.
- **Theorist cryptanalytic depth at large N.** 15 cycles × 5 theories = 75 proposals is a first statistical sample per R3 §8.2. Depth claims require larger samples.
- **DSL coverage of unsupported kinds.** Theorist proposals in `{quagmire, rail_fence, route, myszkowski, key_tape}` will be rejected with `dsl_untranslatable`. This is a known coverage gap, not a campaign failure. The rejection rate on these kinds IS informative.

## 6. Oranchak injection scope

The Oranchak corpora are exposed to the theorist via the new `_render_oranchak_corpora_for_prompt` block:

- `wordlists/quagmire3_keywords_oranchak.txt` — 10,000 English words, community-seeded QIII sweep space.
- `wordlists/quagmire4_keywords_oranchak.txt` — 7,092 words, QIV shape.
- `data/k4_candidate_fills_oranchak.csv` — 19,185 K4-shaped candidate plaintexts for fill-language scoring.

The block carries:
- A usage note pointing theorists at `vigenere` / `variant_beaufort` (DSL-supported) instead of `quagmire` (unsupported).
- An epistemic caveat that these are community-seeded references, not preregistered eliminations.
- An explicit exclusion of `reference/cia_1996_memo.md` (Tier-3).

**Confounding acceptance:** The campaign mixes "R3 architecture evaluation" with "Oranchak content effect." Per the red-team inversion, attribution cost is acceptable because:
- Running the architecture eval on a depleted theorist surface biases against finding signal.
- The null outcome ("no novel signal emerged") is informative either way.
- A positive outcome motivates Campaign B (Oranchak-only or counterfactual A without Oranchak) to isolate the effect.

## 7. Mandatory postmortem (R3 §6.1.7)

After the run, the postmortem **must** capture:

- `total_admissibility_rejections` — count of WorkerContract with status=REJECTED_ADMISSIBILITY.
- `total_override_exhaustion_uses` — theories whose `dsl_spec.override_exhaustion=True` passed admissibility.
- `total_translation_errors` — admissibility rejections whose reasons mention "translation error".
- `matched_null_consultations` — alerts with status `ok_matched_family` or `matched_family_ungated`.
- `matched_null_cache_misses` — alerts with status `matched_null_miss`.
- `dsl_path_contracts` — count with `worker_role="dsl_dispatcher"`.
- `legacy_path_contracts` — count with `worker_role="agent_sdk_non_dsl_category"` or `"agent_sdk"`.
- `programmatic_fallback_cycles` — count of cycles where any candidate had `origin="programmatic_fallback"` (NOT title-pattern grep).
- **Campaign-A addition:** `oranchak_referencing_theories` — count of theories whose `minimal_test_spec` cites an Oranchak path, so we can track whether the prompt injection influenced proposals.
- **Campaign-A addition:** `hardening_halt_triggered` — `{false}` if run completed all 15 cycles, else the `halt_reason_hardening` string.

Plus the pre-existing R3 sections: cycle-by-cycle telemetry, proposal-mortality table with Category-A/B/C split, negative-space finding, failure-mode classification, subscription accounting, architectural finding (D column non-zero check).

## 8. Operator sign-off

Before launch:

- [x] Readiness gate green at commit `3eee572e`
- [x] Campaign-A hardening landed (fallback origin tag, runtime halt counters, Oranchak prompt block, p_value_status plumbed through AlertEvent, 14 new tests green)
- [x] Red-team-disprover reviewed prior pre-hardening plan; showstoppers 1–3 addressed by hardening
- [x] This preregistration document committed before the launch command runs
- [ ] Launch command recorded in run log with timestamp
- [ ] Postmortem mandatory §6.1.7 + Campaign-A additions committed after run

---

*This preregistration locks the success criteria. Any post-hoc weakening of thresholds invalidates the maturation evaluation.*
