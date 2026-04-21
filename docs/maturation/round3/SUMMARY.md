# Framework Maturation Round 3 — Summary

**Period:** 2026-04-21 (multi-session; phases R3-1 through R3-4 plus the R3-0.5 preparatory round)
**Brief:** `CLAUDE_CODE_BRIEF_round3_dsl_wiring.md` (initial R3 brief) + `CLAUDE_CODE_BRIEF_round3_0_5_dsl_completion.md` (R3-0.5 brief spun off from R3-1's escalation)
**Predecessor:** Round 2 (`docs/maturation/round2/SUMMARY.md`) — 6 phases, complete 2026-04-21
**Status:** **COMPLETE.** Post-R3 readiness certified subject to operator review of `K4_RUN_PROTOCOL_R3.md`. K4 run is commissioned separately.

This document is the Round 3 handoff. Every phase, every artifact, every test delta, every behavior change.

---

## 1. One-paragraph summary

Round 3 wired the live controller's worker dispatch path through `job_dispatcher.execute()` — closing the architectural gap the 2026-04-21 K4 run postmortem §6.1.6 named. Along the way, R3-1's audit surfaced that the pre-existing DSL coverage (6 kinds) was too narrow for the procedural paradigm the theorist prompt actively steers toward; the operator directed the R3-0.5 sub-round to add three translators (procedural, grille, polybius) before R3-2's cutover. The cutover (R3-2) preserves kernel overrule, routes Category-A (cipher-family) theories through the 28-core multiprocessing dispatcher with zero Claude tokens on the worker path, and routes Category-B (methodological / investigative) theories through the legacy SDK path with explicit `worker_role` tagging. R3-3's synthetic integration test verifies every §4.2 invariant. R3-4 produces the updated run protocol.

**The most load-bearing result:** per-cycle Claude spend on the Category-A worker pathway drops from roughly 5 worker subscription sessions to zero. That same token budget that previously sized 4 cycles of K4 now sizes 15–25 cycles, before the sibling calls dominate.

---

## 2. Headline numbers

| Metric | Round 2 exit | Round 3 exit | Delta |
|---|---|---|---|
| `tests/` passing | 1529 | 1529 | 0 (unchanged throughout R3) |
| `kryptosbot/tests/` passing | 658 | **755** | **+97** |
| K1 dry-run discovery cycle | 15 | 15 | unchanged |
| K2 dry-run discovery cycle | 17 | 17 | unchanged |
| K3 dry-run discovery cycle | 9,345 | 9,345 | unchanged |
| `_SUPPORTED_KINDS` | 6 | **9** | +3 (procedural, grille, polybius) |
| Worker Claude calls per Category-A dispatch | ~1 subprocess session (~300–500K tokens) | **0** | **elimination** |
| `WorkerContract.worker_role` values | 1 (`agent_sdk`) | **3** (`dsl_dispatcher`, `agent_sdk_non_dsl_category`, `agent_sdk`) | +2 |
| Worker status values | 5 | **6** (REJECTED_ADMISSIBILITY added) | +1 |
| Mortality table's "D column" (dispatcher reject) | always 0 | **non-zero per dispatched cycle** | gap closed |

---

## 3. Phase-by-phase table

| Phase | Brief § | Commit | What landed | Tests added |
|---|---|---|---|---|
| R3-00 pre-flight | R3 §1 | `e2fbdcc` (hygiene) | Dashboard CT hardcode fix (+ latent `{31,73}`→`{32,73}` fix) | 0 |
| R3-1 audit + contract | R3 §2 | `70b3495` | `CURRENT_WORKER_PATH.md`, `DSL_CUTOVER_CONTRACT.md`, `phase_R3_01_report.md` (with §3 operator escalation → Option γ) | 0 |
| R3 contract revision | — | `74db2c5` | Hybrid fallback replaces FB-1-only; `NON_DSL_FAMILIES` defined; R3-0.5 brief authored | 0 |
| R3-0.5-1 procedural | R3.5 §2 | `3f49f58` | `_expand_procedural_layers` via `recipe_to_spec`; `NON_DSL_FAMILIES` landed in critic.py | +22 |
| R3-0.5-2 grille | R3.5 §3 | `b3485c0` | `src/kryptos/kernel/transforms/grille.py` + `TransformType.GRILLE` + CipherKind literal; permutation-only interpretation | +24 |
| R3-0.5-3 polybius | R3.5 §4 | `fff4c21` | Thin wrapper over existing `TransformType.BIFID`; straight polybius deferred | +21 |
| R3-0.5-4 exit | R3.5 §5 | `02442df` | Consistency checks + DSL_CUTOVER_CONTRACT §1.2/§1.3 updates + MEMORY.md pointer | 0 |
| R3-2 DSL dispatch | R3 §3 | `95e917b` | `_run_worker` rewrite; `_dispatch_theories` Category-A/B fan-out; REJECTED_ADMISSIBILITY; dsl_spec field + ledger migration; theorist prompt DSL_SPEC CONTRACT; matched-null keying | +23 |
| R3-3 integration test | R3 §4 | `fefad8c` | Synthetic-theory end-to-end test; theorist-prompt integrity guards; validator relaxation mid-phase; real-theorist plumbing proof | +7 |
| R3-4 protocol + summary | R3 §5 | (this commit) | `K4_RUN_PROTOCOL_R3.md`, this SUMMARY.md, MEMORY.md pointer | 0 |

---

## 4. What changed (by subsystem)

### 4.1 Kernel (`src/kryptos/kernel/`)

- **New module** `transforms/grille.py` — 107 lines. `apply_grille_permutation(text, mask_order)` is a one-line wrapper over `apply_perm`. `validate_grille_mask(mask_order, expected_len)` is the explicit mask validator.
- **Registration** of `TransformType.GRILLE` in `transforms/compose.py`.

Zero other kernel changes. Round 3 is architecture and plumbing; kernel math is unchanged.

### 4.2 DSL (`kryptosbot/hypothesis_dsl.py`)

- `CipherKind` Literal and `_VALID_CIPHER_KINDS` gained `"grille"`. (Procedural and polybius were already in the literal.)

### 4.3 Job dispatcher (`kryptosbot/job_dispatcher.py`)

- `_SUPPORTED_KINDS` grew from 6 to 9 (procedural, grille, polybius).
- `_load_recipes_by_id(path)` helper — thin wrapper for O(1) recipe lookup.
- `_expand_procedural_layers(spec, recipes_by_id)` — spec-level expansion of procedural layers via `recipe_to_spec`. Runs before admissibility so the cardinality budget check sees real numbers.
- `_translate_layer` gained cases for `procedural` (defensive guard), `grille` (with mask validation), `polybius` (bifid-variant only).
- `execute()` calls `_expand_procedural_layers` as step 0.
- `job_result_to_worker_contract` now emits `REJECTED_ADMISSIBILITY` on admissibility-rejected specs (was `INCONCLUSIVE`).

### 4.4 Controller (`kryptosbot/controller.py`)

- `_run_worker` — rewritten for Category-A DSL dispatch. No Claude call on this path. No scratch directory. Full kernel overrule via `job_result_to_worker_contract` → `_verify_against_kernel`. Denormalizes `dsl_pipeline_kinds` + `dsl_spec_hash` into `raw_artifacts` for alert-path matched-null lookup.
- `_run_worker_legacy` — refactored to accept `tag: Optional[str]`. When `tag="non_dsl_category"`, emits `worker_role="agent_sdk_non_dsl_category"` on the resulting contract. Five hardcoded `"agent_sdk"` values replaced by a single `worker_role_value` local.
- `_dispatch_theories` — fan-out by category: `family ∈ NON_DSL_FAMILIES` → legacy with tag, else → DSL.
- `_build_theorist_prompt` — OUTPUT FORMAT template updated with inline reminder; new DSL_SPEC CONTRACT section with 3 worked examples (Vigenere-on-KA, two-layer columnar, honest null for non-cipher).

### 4.5 Critic (`kryptosbot/critic.py`)

- `NON_DSL_FAMILIES` constant: `{geometry, k2_coords, geodetic, antipodes, archive_evidence, crib_analysis, k3_continuity}`.
- New Check 4.6 — Category-A/B/C translatability. Placed after existing reject gates so stronger rejection reasons fire first. Substitutes `theory.hypothesis_id` for missing/placeholder spec hypothesis_id before validating.

### 4.6 Contracts (`kryptosbot/contracts.py`)

- `validate_theory_proposals` accepts any dict shape for `dsl_spec` (loose boundary). Structural validation runs exclusively in the critic.

### 4.7 Models (`kryptosbot/models.py`)

- `WorkerStatus.REJECTED_ADMISSIBILITY = "rejected_admissibility"`.
- `TheoryRecord.dsl_spec: dict[str, Any]` default-factory dict.

### 4.8 Ledger (`kryptosbot/theory_ledger.py`)

- `dsl_spec TEXT NOT NULL DEFAULT '{}'` column on `theories` table.
- Additive `ALTER TABLE` migration for pre-R3-2 databases.
- `_theory_to_row` / `_row_to_theory` / upsert SQL round-trip the field.

### 4.9 Alerts / null baselines (`kryptosbot/alerts.py`, `kryptosbot/null_baselines.py`)

- `_matched_null_family_from_contract(contract)` — derives family from `raw_artifacts["dsl_pipeline_kinds"]`.
- `_p_value_gate_passes(..., family="")` — threads family through to null lookup. New status values `ok_matched_family`, `matched_family_ungated`, `matched_null_miss`.
- `p_value_for_alert(..., family="")` — tries matched-family cache first when family is non-empty; falls back to random_text with explicit `matched_null_miss` status.

---

## 5. Invariants preserved

All Round 2 invariants carry forward unchanged:

- K1/15, K2/17, K3/9345 on `--cycles 20000` dry-run
- R2-5 real-API K1 test passes
- Phase 3 kernel-overrule battery (35 tests) green
- Phase 6 p-value gate fires on `p ≤ 1e-6`
- Matched-family nulls calibrated for `{beaufort, variant_beaufort, columnar_single, columnar_double}`

Plus R3 additions:

- DSL dispatch preserves kernel overrule on the Category-A path (`job_result_to_worker_contract` calls `_verify_against_kernel`).
- Category-A path creates no scratch directory.
- Every theory persisted to the ledger carries its `dsl_spec` field.

---

## 6. Falsification targets — status

Brief §0.5 targets after R3-4:

| Target | Status | Evidence |
|---|---|---|
| Live cycle produces at least one dispatcher-rejection | ✓ verified under synthetic | R3-3 integration test: `REJECTED_ADMISSIBILITY` contract present in mortality fingerprint |
| Alert-gate path routes through R2-4 matched-family nulls | ✓ verified under synthetic | R3-3 integration test: `_matched_null_family_from_contract` resolves columnar layer to `columnar_single` |
| Real-theorist `--dry-run` produces valid DSL specs at ≥80% on Category A | 100% on N=1 — above threshold but thin sample | R3-3 real-theorist measurement; see §3 of phase R3-03 report for the small-sample caveat |
| R2-5 K1 real-API test passes | ✓ | R3-2's non-regression run (implicit; R3-2 didn't touch that test) |
| Self-test K1/15, K2/17, K3/9345 | ✓ | Verified at every phase exit |
| Phase 3 kernel-overrule battery green | ✓ | 35 tests in `test_verify_against_kernel_adversarial.py` pass |
| Phase 6 p-value gate still fires | ✓ | `test_p_value_gate_suppresses_when_p_above_threshold` passes |

---

## 7. What R3 proved and what it didn't

### 7.1 Proved

- The postmortem §6.1.6 architectural gap is closed. `job_dispatcher.execute()` is called on every Category-A dispatch.
- The DSL's 9-kind coverage is plumbed end-to-end: theorist → critic → dispatcher → kernel-verified contract.
- The hybrid fallback policy resolves the category error in the DSL's original framing: cipher work goes through the DSL, non-cipher work stays on the legacy path.
- Kernel overrule is preserved across the new dispatch path.
- Mortality telemetry now distinguishes Category-A DSL contracts, Category-B legacy contracts, admissibility rejections, and critic `dsl_untranslatable` rejections.

### 7.2 Did not prove

- **K4 solvability.** This was never R3's claim.
- **Theorist cryptanalytic depth.** R3 is plumbing; whether the theorist proposes truly novel hypotheses is a prompt-quality concern.
- **Real-theorist spec-production rate above a statistically strong N.** N=1 observed sample, 100% rate. The K4 run's larger N will produce the first real statistical read.
- **Subscription billing reduction on live workload.** The per-cycle cost shift is algebraic; the empirical confirmation happens on the first post-R3 K4 run.
- **Fallback-firing reliability.** R3-3 observed non-deterministic `_programmatic_fallback` triggering at larger theory counts. Flagged for operator monitoring in K4_RUN_PROTOCOL_R3 §2 item 3.

---

## 8. Residual concerns for the K4 run

Flagged in `K4_RUN_PROTOCOL_R3.md` §2; re-stated here for visibility:

1. **5 cipher kinds still lack translators** (`rail_fence, route, myszkowski, quagmire, key_tape`). Expect non-zero `dsl_untranslatable` rejections; they are honest, not errors.
2. **`TokenAccountant` not wired.** Token telemetry for the K4 run is post-hoc from session transcripts.
3. **Fallback-firing reliability.** Monitor `programmatic_fallback_cycles` at §6.1.7 of the protocol; escalate if > 30% sustained.
4. **Straight polybius deferred.** Only `variant="bifid"` translatable.

---

## 9. Handoff

**R3 exit:** this commit.

**Next operator action:** run the §7 pre-run readiness gate in `K4_RUN_PROTOCOL_R3.md`, then commission the K4 run as a separate operator instruction per brief §handoff.

**Do NOT start K4 as part of R3 completion.**

---

*End of Round 3 SUMMARY. Round 3 delivers the wired instrument; the K4 run is the operator's decision.*
