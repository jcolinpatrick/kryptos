# K4 Run Protocol

**Date authored:** 2026-04-21
**Author:** Claude Code Opus 4.7 (under Round 2 maturation brief)
**Status:** awaiting operator approval before any K4 compute starts
**Supersedes:** nothing — this is the first K4 run protocol document
**Amendments:** 2026-04-21 (operator review): §3.1 first-run defaults tightened to 15 cycles / $25; §5 restructured with explicit §5.2 "nothing fires" terminal state; §6.1 mortality table spec made required (not advisory); §7 sign-off updated.

This document is the single point where the framework's automation
hands control back to the human for the go/no-go decision. **Claude
Code does not start the K4 run.** The operator starts the K4 run
after reading and explicitly approving this document.

---

## 1. Framework fitness summary (what R2-1 through R2-5 proved)

### 1.1 Dry-run panel status

| Panel | Status | Evidence |
|---|---|---|
| K1 | **[DERIVED FACT]** rediscovered in 15 cycles | Phase 7 + R2-1 self-test; 2026-04-21. `results/self_test/r2_1_final.json` |
| K2 | **[DERIVED FACT]** rediscovered in 17 cycles | Phase 7 + R2-1 self-test; `results/self_test/r2_1_final.json` |
| K3 | **[DERIVED FACT]** rediscovered in 9,345 cycles (was missing at Round 1 exit) | R2-1; columnar_double strategy; `results/self_test/r2_1_final.json` |

All three dry-run discoveries are **kernel-verified** (no worker self-report), **strategy-search-based** (generic enumeration with priority-tiered ordering recipes), and produce **zero false-positive BREAKTHROUGH** events across the full schedule. Total dry-run wall time: ~0.87 seconds.

### 1.2 Real-API K1 pass status

**[INTERNAL RESULT]** Claude Opus 4.7 given K1's challenge (CT + 20 pseudo-cribs + framework capability summary) proposed `vigenere × KA × PALIMPSEST`; the R2-2 dispatcher translated the spec; the kernel recovered K1 plaintext exactly at pseudo_crib_score 20/20 on the **first API call**. Repro: `results/self_test/r2_5_real_k1.json`.

- Cost: $0.0282
- Wall time: 6.16s
- Tokens: 934 in + 189 out
- Turns: 1

**Honest nuance:** Claude's own reasoning identifies K1 as a well-known Kryptos panel. The theorist step was **recognition, not derivation**. K1 is in Claude's training data; K4 is not-yet-solved and therefore lacks a "known answer" to recognize. R2-5 validates the framework's **execution chain** (DSL → dispatcher → kernel → scoring), not the theorist's cryptanalytic capacity. K4 requires the theorist to *derive* a spec, not *recall* one.

### 1.3 Null-baseline calibration status

**[DERIVED FACT]** 7 matched nulls in the manifest (`null_baselines/manifest.json`):

- Phase 6: `crib_score × matched_variant_family × vigenere` (legacy).
- R2-4: `crib_score × matched_variant_family × {beaufort, variant_beaufort, columnar_single, columnar_double}` (4).
- R2-4: `ngram_score × matched_variant_family × {columnar_single, columnar_double}` (2).

50K samples each for R2-4 entries. Empirical floor 1/N = 2 × 10⁻⁵ documented.

K3's published plaintext under the `ngram_score × columnar_double` null: extreme beyond the 1/N floor (~40 stdevs above mean), per `test_k3_pt_is_extreme_vs_columnar_double_null`.

### 1.4 Coverage surface

After Round 2, the framework can express + dispatch + score:

- Vigenère / Beaufort / Variant-Beaufort on **AZ, KA, keyword_mixed** alphabets (R2-2).
- Single-layer columnar transposition (Phase 4).
- **Two-layer columnar transposition** (R2-1 Path A).
- Any two-layer composition whose individual layers are in the supported set (implied by Phase 4 pipeline mechanics — multi-layer substitution + transposition).

It can NOT yet express:
- Bifid / Polybius families (DSL kinds declared but dispatcher translation deferred per R2-2 §3.2).
- Autokey variants (proven impossible on K4 by prior work; not a gap).
- Quagmire I/II as first-class kinds (Quagmire III is reducible to Vigenère-on-KA; I/II would need separate dispatcher work).
- Procedural / hand-executable recipes beyond what `procedural_enumerator` already enumerates.

---

## 2. Known coverage gaps

Consolidated from all Round 1 and Round 2 phase reports. Each item classified by K4-solve-probability impact.

### 2.1 Gaps that plausibly block K4 solve (audit before starting)

| Gap | Source | K4 impact | Detectable during run? |
|---|---|---|---|
| **Kernel-scoring K4-specificity.** `score_candidate` reads module-level `CRIB_DICT` / `BEAN_EQ` / `BEAN_INEQ` / `BEAN_LINEAR`. These ARE the K4 constants, so for K4 work this is correct. For self-test work (R2-5+) it required override via `CT_LEN` patching. **No K4 impact** — these are the right values for K4. | Round 2 R2-5 report §1 | None | N/A |
| **Theorist step's training-data effect.** R2-5 demonstrated that Claude recognizes K1 rather than deriving it. K4 has no known solution, so there's nothing to recognize. But the model may retrieve *eliminated* K4 hypotheses from training data and propose them as "novel." | R2-5 §6.2 | **Moderate** — the critic's Tier 1/2 elimination list + R2-3 override-duplicate guard are designed for this, but may be incomplete for hypotheses that have been discussed informally in Kryptos community threads. | **Yes** — every proposal goes through the critic. Watch for rejections citing tier 1/2 or override_duplicate. |
| **Full persona controller + sibling calls not exercised end-to-end for a self-test panel.** R2-5 shipped loop-lite. The full persona / red-team / stat-audit / synthesis chain has only been exercised against K4 itself in prior rounds. | R2-5 §1 | **Low-to-moderate** — the persona + sibling chain has daily operator-verified history but has not been wrung out against a known-answer panel. | **Yes** — the K4 run will generate telemetry on every stage. First crib≥18 alert is the load-bearing moment. |

### 2.2 Gaps that do NOT plausibly block K4 solve

| Gap | Reason not blocking |
|---|---|
| Bifid / Polybius dispatcher translation absent | Bifid is impossible on K4 (all 26 letters appear in CT); Polybius families have been broadly eliminated. |
| K2 / K3 real-API runs not executed | K2 is the same cipher family as K1 (trivially succeeds); K3 tests the R2-1 double columnar path which is kernel-verified via dry-run. Additional real-API runs would add no new information at $0.10 cost. |
| ~380 of 532 AAA archive photos sparse-sampled (not individually examined) | Documented in `project_deferred_archive_photo_batch_pass.md`. Not known to block; dense-region samples captured research signal. |

### 2.3 Will the K4 run detect the blockers if they fire?

- Kernel-scoring K4-specificity: N/A (not a blocker for K4).
- Training-data retrieval: yes — critic + override-duplicate reject it; R2-3 guard in place.
- Persona controller fitness: yes — an alert at crib ≥ 18 exercises every downstream stage. A malfunction shows up as either a false-positive alert (caught by Phase 6 p-value gate at 1e-6) or a dropped alert (caught by the alert-handling runbook §4).

---

## 3. K4 run protocol

### 3.1 Duration caps (first-run defaults)

- **Cycle cap:** `max_cycles = 15` for the first run. Deliberately tight.
- **USD cap:** `$25.00` for the first run. Deliberately half the "natural" cap.

**Why half:** the most likely outcome of a first K4 run is **outcome (1) below** — 15 cycles complete, nothing signals. Under that outcome the post-run mortality table (§6.1) will tell us where the framework is under-performing. Burning $50 on a first pass that turns out to be dominated by easy-to-diagnose issues (theorist concentrating on eliminated families, say) is wasted compute; the diagnostic value plateaus quickly once the failure mode is evident.

Keeping $25 of budget in reserve allows a second informed run with prompt adjustments driven by the §6.1 post-mortem, rather than spending the full budget on a first pass that is about to be superseded. If the first run does fire a SIGNAL, §4 handles it and the reserve is unused.

The TokenAccountant from R2-5 can enforce the cap if wired into the controller's API call path (operator may need to do this wiring or use the existing `controller.ConfigConfig.budget_usd` field if already present).

### 3.2 Theorist rotation

- Persona pool: whatever the current `pantheon/` configuration enumerates.
- Per cycle: `theories_per_cycle = 5` (current default).
- Rotation: controller's existing persona-selection logic (not changed by Round 2).

### 3.3 Active filters

| Filter | State for K4 run |
|---|---|
| Red-team-disprover sibling call | **ACTIVE** — Day 3 wiring (per MEMORY.md). |
| Stat-audit gate (Day 5) | **ACTIVE** — threshold `stat_audit_threshold = 18`. |
| Null-baseline p-value gate | **ACTIVE** — Phase 6 gate at `p ≤ 1e-6`. With R2-4 matched-family nulls now available, transposition-path alerts route through the columnar null. |
| Lead-pursuit evaluator (Day 6) | **ACTIVE** — crib range [6, 17]. |
| Critic Tier 1/2 eliminations | **ACTIVE** — K4 single-layer eliminations remain authoritative. |
| Exhaustion-overlap check | **ACTIVE**; R2-3 override available when theorist provides a justification. |

### 3.4 Novel families enabled specifically for K4

None. R2-4's matched-family nulls are new, but the families they target (beaufort, variant_beaufort, columnar_single, columnar_double) have been active in the search for prior rounds. The nulls just make their alert-gate math correct.

If the operator wants to enable a novel family (e.g., a hand-executable procedural recipe not in the existing enumerator), that requires a fresh DSL kind + dispatcher translation + calibrated null and should be authored as its own phase.

---

## 4. Alert handling runbook

Phase 6's p-value gate at `p ≤ 1e-6` is the last line of defense against false alerts. When an alert fires, the operator's checklist is:

### 4.1 Immediate (pre-celebration) checks

1. **Verify kernel overrule.** Look at the worker's `alert_payload` for `fields_overwritten: true`. If set, the worker's claim was corrected by the kernel — the reported `crib_score` is what the kernel computed, not what the worker said. This is normal and means the system worked.

2. **Check `bean_variant`.** All three variants (vigenere / beaufort / variant_beaufort) must be checked. A true K4 break fires on one variant; a worker that reports a single variant match without specifying which may be wrong.

3. **Re-run independently from checkpoint.** The same spec dispatched from a fresh controller process must produce the same crib_score. If not, the kernel is non-deterministic or there's state leak.

4. **Compare against matched-family null.** The alert's p-value should come from the R2-4 matched null for the alert's family (columnar_single/double for transposition alerts; beaufort/variant_beaufort/vigenere for substitution). A p-value from the wrong null is noise.

5. **Check for similar-keyword hallucination.** If the spec's keyword is close in Jaccard to a retired hypothesis's keyword, the model may have confabulated a variant. Cross-check against `memory/retired/`.

### 4.2 Fuller validation (only after step 4.1 passes)

6. Run the **full Round 1 Phase 3 adversarial battery** against the candidate PT — kernel-verify cribs, bean-verify constraints, score under all three matched-family nulls, check for text coherence beyond the crib positions.

7. If the candidate survives step 6, **HALT the controller** and invoke `red-team-disprover` on the candidate's assumption bundle.

### 4.3 What NOT to do

- **Do not** tune prompts in response to a borderline alert. Round 2 R2-5 established the "one pass, no retries on non-infrastructure failure" principle; the K4 run inherits it.
- **Do not** reduce the p-value threshold below 1e-6 because "we're close." The gate is the gate.
- **Do not** silently merge a promoted theory into `MEMORY.md` before the validation checklist passes.

---

## 5. Halt / terminal conditions (pre-committed)

The K4 run ends in exactly one of the following states. Four are **mid-run halts** (the controller stops early); one is the **natural terminal state** (the run completes cleanly without firing a SIGNAL). The operator commits to all five handlings in advance.

### 5.1 Mid-run halts — stop immediately

The operator halts the run **immediately** on any of:

1. **Budget exhausted.** TokenAccountant's `exceeded()` returns True, OR the operator-selected USD cap is reached.
2. **Three consecutive cycles with all proposals rejected at critic.** This indicates either a collapsed theorist (needs manual intervention) or a theorist proposing only eliminated ideas (prompt drift — operator must refresh the elimination ledger into the prompt).
3. **Kernel-overrule event where `fields_overwritten=true` AND worker's self-reported claim was `crib_score=24`.** One such event is strong evidence the kernel-overrule path itself has regressed — pending audit, the run must stop so we don't chase a worker artifact.
4. **Any verified `crib_score=24` with `p ≤ 1e-6`.** Halt, run §4 battery, do NOT celebrate until §4 passes.

### 5.2 Natural terminal state — expected most likely outcome

5. **Run completes cleanly at `max_cycles` without a SIGNAL.** The `theories_per_cycle × max_cycles = 5 × 15 = 75` proposals all went through critic / red-team / dispatcher / scoring without any candidate reaching `crib_score >= 18` at `p <= 1e-6`.

This is **outcome (1) — the expected most likely outcome** of a first K4 run under this protocol. It is NOT a failure state; it is the designed behavior for "the framework ran, nothing crossed the SIGNAL threshold, now we learn from what was tested."

When outcome (5) occurs:

- Do NOT treat it as "the run ended" and stop thinking.
- Do NOT immediately launch a second run with tweaked parameters.
- Do NOT conclude "K4 is unsolvable by this framework."
- DO execute §6.1 — the post-run analysis procedure — in full. The proposal-mortality table is the diagnostic signal; skipping it wastes the first run's information.
- DO hold the $25 reserve until the §6.1 post-mortem classifies the failure mode. The classification informs whether a second run (with a prompt adjustment derived from the mortality table) is likely to be productive or whether a new brief is warranted.

---

## 6. Post-run analysis procedure

### 6.1 If K4 is NOT solved (including the natural §5.2 terminal state)

Produce `docs/maturation/round2/K4_RUN_POSTMORTEM.md` with **all of** the following sections. The table in §6.1.2 is REQUIRED, not optional; skipping it forfeits the first run's diagnostic value.

#### 6.1.1 Cycle-by-cycle telemetry

One row per cycle with: cycle number, # theories proposed, # approved by critic, # dispatched, best `crib_score` observed that cycle, best `p_value_vs_null` observed that cycle, cumulative USD spent. Source of truth: the ledger DB (`db/k4_run_<date>.sqlite`) + `results/` artifacts.

#### 6.1.2 Proposal-mortality table (REQUIRED)

A single table answering **"where did proposals die?"** Every proposal that entered the loop belongs to exactly one row. Counts sum to total proposals. If a stage was skipped (e.g., critic rejected before dispatch), the proposal is credited to the earliest-stage death, not the skipped later stages.

| Stage | Sub-reason | Count | % of total |
|---|---|---|---|
| **A. Theorist never proposed** | Family `X` absent from proposals | | |
| | Keyword space `Y` absent | | |
| | No procedural recipe referenced | | |
| **B. Critic rejected** | `REJECT_DUPLICATE` (regular — §3 similar-theories) | | |
| | `REJECT_DUPLICATE` (R2-3 override-justification collision) | | |
| | `REJECT_ELIMINATED` (Tier 1 family) | | |
| | `REJECT_ELIMINATED` (Tier 2 single-layer family) | | |
| | `REJECT_ELIMINATED` (retired palette / null-mask revival) | | |
| | `REJECT_UNDERCONSTRAINED` (scope / falsifiability hygiene) | | |
| | `REJECT_CONTRADICTED` (claims-registry conflict) | | |
| | `REJECT_LOW_INFORMATION` | | |
| | `DEFER` | | |
| **C. Red-team killed** | `CONCERNED` with `search_space_risk=unbounded_search` | | |
| | `CONCERNED` with `search_space_risk=exhausted_source_material` | | |
| | `CONCERNED` with `search_space_risk=underconstrained` | | |
| | `CONCERNED` with `search_space_risk=duplicate_family` | | |
| | `CONCERNED` with other `search_space_risk` | | |
| | `DISPROVE` (strong mechanical contradiction) | | |
| **D. Dispatcher rejected** | admissibility: budget overflow | | |
| | admissibility: exhaustion overlap (no override) | | |
| | admissibility: translation gap (unsupported DSL kind) | | |
| | translation error at `_build_pipeline_config` | | |
| **E. Scoring outcomes (dispatched)** | `crib_score < STORE_THRESHOLD` (below 6) | | |
| | `crib_score ∈ [6, 9]` — noise-band | | |
| | `crib_score ∈ [10, 17]` — interesting / lead-pursued | | |
| | `crib_score ∈ [18, 23]` — SIGNAL, failed p-value gate | | |
| | `crib_score ∈ [18, 23]` — SIGNAL, passed p-value gate | | |
| | `crib_score = 24` — verified BREAKTHROUGH | | |
| **F. Error / infra** | worker timeout | | |
| | kernel error during scoring | | |
| | API failure / rate-limit / retry-exhausted | | |
| **TOTAL** | | | 100% |

Every `Count` cell must be filled. Cells with zero are also filled as zero — an absent cell is ambiguous.

**For row A (Theorist never proposed)**, the "target list" against which proposals are measured is the **post-eliminations admissible family × primary-keyword-class space**, specifically:

- Cipher families: the `_SUPPORTED_KINDS` set from `job_dispatcher.py` minus Tier 1 / Tier 2 single-layer eliminations, plus any multi-layer composition families enumerated by `procedural_enumerator`.
- Keyword classes: the thematic-keyword-list buckets in `src/kryptos/kernel/alphabet.py::THEMATIC_KEYWORDS` + Sanborn / Scheidt vocabulary buckets in `docs/procedural_recipes.json`.
- Procedural recipes: every `PROC-P-*` id in `docs/procedural_recipes.json`.

A family / keyword / recipe is "absent from proposals" if it appears in the target list but zero proposals in the run referenced it. Partial matches (a keyword from the bucket appeared but not the specific variant) count as present.

#### 6.1.3 Negative-space finding

Given the mortality table, answer: what does the tested-and-failed set tell us about where the K4 search space likely doesn't live? Confine claims to families that actually got dispatched (rows E) — row B/C/D rejections tell us about the filters, not about K4.

#### 6.1.4 Failure-mode classification

Pick the ONE row with the largest count and classify the failure mode:

- **Mode A1** (theorist concentrated on eliminated families) → next brief: "improve theorist derivation under strict elimination context." NOT another maturation round.
- **Mode A2** (theorist missed a large open-search region) → next brief: "expand theorist prompt scope / add pursuit leads for region X."
- **Mode B** (critic rejected disproportionately) → investigate whether Tier 2 is over-eager or the retired-palette matcher false-positive-prone.
- **Mode C** (red-team killed disproportionately) → investigate search_space_risk classifier.
- **Mode D** (dispatcher rejected for admissibility / translation) → gap in DSL coverage.
- **Mode E (below 6)** (framework ran cleanly, nothing scored above noise) → this is "the instrument works but the hypothesis space doesn't contain K4." Next brief: expand the hypothesis space, not the instrument.
- **Mode E (6-17 band populated, nothing crossed 18)** → the framework has candidates but none are strong. Lead-pursuit should have fired; check whether lead-pursuit produced follow-ups and whether they were executed.
- **Mode F** (errors / infra) → infrastructure fix, then re-run.

The classification drives the next brief. Without it, "run again with different settings" is cargo-culted.

#### 6.1.5 Budget accounting

Total USD + token count per model; consistency check against the pre-run forecast and against the per-cycle telemetry. An unexpected blow-up in any cycle is a signal that a persona is looping or a worker is retrying silently.

### 6.2 If K4 IS solved

Stop. Do not update any ledger, do not push to remote, do not talk about it on any channel. The operator owns the disclosure decision entirely.

The post-solve checklist (for the operator):
- Reproduce from a clean process (fresh interpreter, fresh DB).
- Independent verification: the solved PT must be re-derivable by a human-readable procedure that does not require the framework — i.e., the framework's role is "proposed the key" and the key must decrypt the CT under a standard cipher definition. If not, the result is a framework artifact, not a real solve.
- Publication-readiness gate: multi-round review with an independent cryptographer. The framework is not the primary evidence; it's the proposer.

---

## 7. Sign-off checklist

Before operator starts the K4 run:

- [ ] Read sections 1-6 above.
- [ ] Confirmed `ANTHROPIC_API_KEY` is set and corresponds to the account authorized for the spend.
- [ ] Confirmed the TokenAccountant cap is **$25.00** (first-run default per §3.1, tight by design to preserve $25 reserve for an informed second run).
- [ ] Confirmed `max_cycles = 15` (first-run default per §3.1). 15 × 5 = 75 proposals should be enough for the mortality table to classify the failure mode cleanly.
- [ ] Confirmed a fresh `db/k4_run_<date>.sqlite` target DB is configured — do NOT run into the live research ledger on the first attempt.
- [ ] Read §4 alert runbook and §5 halt / terminal conditions. Mentally committed to:
    - the "do not celebrate until §4 validation passes" rule.
    - treating §5.2 (nothing fires) as the **expected most likely outcome**, not a failure.
    - executing §6.1's full mortality table even if §5.2 is what happens — the table is the first run's diagnostic value.
- [ ] Confirmed the $25 reserve is held until §6.1 post-mortem classifies the failure mode.

Once all are checked: start the run.

---

*This document is the Round 2 handoff contract. Round 2 ends here. K4 is the operator's decision.*
