# Phase R3-2 — DSL Dispatch Cutover

**Date:** 2026-04-21
**Brief:** R3-2 commissioning instruction; DSL_CUTOVER_CONTRACT §9 acceptance criteria
**Phase result:** Complete. 23 new tests, all green. Self-test unchanged.

---

## 1. What landed

### 1.1 `models.py` — enum + field additions

- `WorkerStatus.REJECTED_ADMISSIBILITY = "rejected_admissibility"` — the dispatcher-reject terminal state demanded by brief §0.5 (the postmortem's "Row D" column).
- `TheoryRecord.dsl_spec: dict[str, Any] = field(default_factory=dict)` — per-theory DSL specification attached by the theorist.

### 1.2 `theory_ledger.py` — schema migration

- New column `dsl_spec TEXT NOT NULL DEFAULT '{}'` on the `theories` table.
- Additive migration in `_ensure_schema`: pre-R3-2 databases get the column added via `ALTER TABLE` with empty-string default; R3-2-initialized databases get it at creation time.
- `_theory_to_row` / `_row_to_theory` / upsert SQL updated to round-trip the field.

### 1.3 `contracts.py::validate_theory_proposals` — DSL boundary validation

Parses incoming theory proposals with explicit three-way handling of `dsl_spec`:

- **Missing or `null`** → valid theory with `dsl_spec={}`.
- **Dict** → parsed via `validate_hypothesis_spec`; structural failures land the whole theory in `invalid` with per-error reasons.
- **Non-dict, non-null** → rejected at boundary (e.g., theorist emits a string).

### 1.4 `critic.py` — Category-A/B/C classification

New Check 4.6 added **after** the existing reject gates (completeness, family-elimination, retired-palette, consensus-null, duplicate, override-duplicate, contradiction, prompt-surface-scope) — ordering rationale in the critic docstring. A Tier-1 eliminated cipher-family theory is better reported as "eliminated" than as "no DSL spec."

Flow:

- `family in NON_DSL_FAMILIES` → Category B → skip the check entirely.
- `dsl_spec == {}` → Category C → reject with `dsl_untranslatable` (theorist declared null on a cipher-family theory).
- `validate_hypothesis_spec(dsl_spec).is_valid is False` → Category C → reject with validation errors attached.
- Any pipeline layer with `kind not in _SUPPORTED_KINDS` → Category C → reject listing the untranslatable kinds and the supported set.

`_SUPPORTED_KINDS` is read at runtime, so R3-0.5's 9-kind set is honoured automatically; growing it further in a later brief requires no critic change.

### 1.5 `controller.py` — dispatch rewrite

**New `_run_worker`** (Category A path):

1. Parse `theory.dsl_spec` into a `HypothesisSpec` (revalidation as defense-in-depth).
2. Call `check_admissibility(spec)`. Reject → `WorkerStatus.REJECTED_ADMISSIBILITY` contract with admissibility reasons in `disproof_evidence`, no compute spent, early return.
3. `await asyncio.to_thread(execute, spec)` — dispatches via `multiprocessing.Pool(cpu_count() - 2)` inside `job_dispatcher.execute`.
4. Convert `JobResult` → `WorkerContract` via `job_result_to_worker_contract` which internally calls `_verify_against_kernel` (Phase 3 overrule preserved).
5. Denormalize pipeline kinds and spec hash into `contract.raw_artifacts` for alert-path matched-null lookup.
6. Persist experiment + defensive cleanup pass (no-op on DSL path since no scratch dir was created).

**No Claude call on this path.** Per-cycle Claude spend on the worker pathway drops to zero. Only the theorist (once per cycle) and sibling agents (red-team, stat-audit, synthesis, pursuit) still call Claude.

**`_run_worker_legacy`** refactored to accept `tag: Optional[str]` kwarg. When `tag="non_dsl_category"`, all WorkerContract instances produced by the legacy path carry `worker_role="agent_sdk_non_dsl_category"`. The five hardcoded `"agent_sdk"` role values in the legacy body were replaced by a single `worker_role_value` local.

**`_dispatch_theories`** now fans out per DSL_CUTOVER_CONTRACT §2.5:

```python
if family_lower in NON_DSL_FAMILIES:
    tasks.append(self._run_worker_legacy(theory, ..., tag="non_dsl_category"))
else:
    tasks.append(self._run_worker(theory, ...))
```

The `asyncio.gather(return_exceptions=True)` path is preserved for both categories; ERROR contracts carry the correct `worker_role` per dispatch path.

### 1.6 `controller.py::_build_theorist_prompt` — DSL contract docs

Replaced the "OPTIONAL: dsl_spec may contain..." paragraph with an explicit DSL_SPEC CONTRACT section including:

- Category-A requirement statement (cipher-family theories MUST include a spec).
- Category-B exception list (NON_DSL_FAMILIES).
- Post-R3-0.5 supported-kinds list.
- Untranslatable-kinds list with rejection consequence.
- Three worked examples — Example A (single-layer Vigenere on KA), Example B (two-layer columnar+Vigenere), Example C (honest null for non-cipher theory).
- Explicit guidance against fabricating specs ("set dsl_spec=null and accept rejection").

### 1.7 `null_baselines.py` + `alerts.py` — matched-null keying (R2-4 integration)

`p_value_for_alert` gained optional `family: str = ""` kwarg. When non-empty:

- Try matched-family null cache first (status `"ok_matched_family"`).
- On matched-family cache miss, fall back to `random_text` and flag status `"matched_null_miss"` for operator log.
- Empty family preserves Phase-6 behaviour exactly.

`alerts._matched_null_family_from_contract` derives the family tag from `contract.raw_artifacts["dsl_pipeline_kinds"]`:

| Pipeline kinds | Derived family |
|---|---|
| `["columnar"]` | `columnar_single` |
| `["columnar", "columnar"]` | `columnar_double` |
| `["beaufort"]` | `beaufort` |
| `["variant_beaufort"]` | `variant_beaufort` |
| `["vigenere"]` | `vigenere` |
| anything else (multi-kind, grille, polybius, procedural) | `""` (random_text fallback) |

`_p_value_gate_passes` threads the derived family through to the null lookup. Two new status values are added: `"ok_matched_family"` (p ≤ gate, matched null used) and `"matched_family_ungated"` (p > gate, matched null used) so the gate's log line records which null fired.

### 1.8 `job_dispatcher.py::job_result_to_worker_contract`

One-line semantic change: admissibility-rejected job results now produce `WorkerStatus.REJECTED_ADMISSIBILITY` instead of `INCONCLUSIVE`. This is the status value the new `_run_worker` relies on.

---

## 2. Architectural payoff (brief special instruction)

**The worker stops calling Claude.** This is the round's central shift.

Pre-R3-2 per-cycle Claude cost on the worker pathway (Category A):
```
5 workers/cycle × N_turns_per_worker × cost_per_turn
```

Post-R3-2 per-cycle cost on the worker pathway (Category A):
```
0 (workers are pure Python compute on the 28-core pool)
```

Category-A theories cost zero tokens to dispatch. The only remaining Claude calls per cycle are:

- **Theorist:** 1 call per cycle.
- **Critic:** 0 calls (deterministic Python).
- **Red-team sibling:** 1 call per approved theory (unchanged).
- **Stat-audit sibling:** ≤1 call per dispatched Category-A contract (unchanged).
- **Synthesis sibling:** 1 call per cycle (unchanged).
- **Pursuit evaluator sibling:** ≤1 call per sub-signal contract (unchanged).

Category-B theories still call Claude through `_run_worker_legacy` — that path remains live per DSL_CUTOVER_CONTRACT §6.1. But Category B is the minority per theorist output distribution (NON_DSL_FAMILIES = 7 families of ~15 typically active), and its throughput is bounded by the theorist's rate of methodological proposals, not by the dispatcher.

**Implication for K4 budget calculus:** the pre-R3 K4 run (2026-04-21 postmortem) consumed 1.8M output tokens over 4 cycles, dominated by worker subprocess output. Under R3-2's architecture, that same cycle count for Category-A theories is effectively free. The theorist+siblings cost per cycle is small enough that 50 cycles becomes feasible where 4 previously was the operator's ceiling.

This cost shift is documented in the R3-4 updated run protocol (`K4_RUN_PROTOCOL_R3.md`).

---

## 3. Scratch directory elimination (brief §3.4)

Brief asserts as a correctness test: "worker does not write to `worker_scratch/`" on the Category-A path.

Verified by `test_run_worker_does_not_create_scratch_directory`:

- Dispatches a synthetic Category-A theory through the real `_run_worker`.
- After dispatch completes, asserts `<tmp_path>/results/worker_scratch/` either does not exist or is empty.
- Test passes — the new `_run_worker` never calls `_worker_scratch_dir()` or `mkdir`. All DSL artifacts go to `results/dsl_jobs/<hypothesis_id>_<spec_hash>/` via `job_dispatcher.execute`.

---

## 4. Tests

### 4.1 New file `kryptosbot/tests/test_r3_2_dsl_dispatch.py` — 23 tests

Structured per brief §3.8 acceptance scenarios plus DSL_CUTOVER_CONTRACT §9 hybrid-split scenarios:

**models.py additions (3):** enum value, default field value, round-trip persistence.

**contracts validation (4):** null spec accepted, valid spec accepted, non-dict rejected, structurally-invalid rejected.

**Critic Category-A/B/C (4):** cipher w/o spec rejected, cipher w/ untranslatable kind rejected, non-cipher skips DSL check, cipher w/ valid spec approved.

**job_result_to_worker_contract (1):** REJECTED_ADMISSIBILITY mapping.

**Matched-null family derivation (5):** columnar_double, columnar_single, beaufort, legacy-empty, mixed-pipeline-empty.

**Live `_run_worker` (3):** scratch directory not created, kernel overrule preserved, admissibility-reject path produces REJECTED_ADMISSIBILITY with raw_artifacts.

**Hybrid split (3):** Category-B legacy dispatch with tag, Category-A DSL dispatch, mixed batch distinguishes categories by worker_role.

Brief minimum was 12; delivered 23 because adversarial coverage of every new code surface needed its own negative test.

### 4.2 Pre-existing test updates

- `test_job_dispatcher.py::test_admissibility_rejection_becomes_inconclusive` → renamed to `test_admissibility_rejection_becomes_rejected_admissibility`; uses `rail_fence` (still unsupported) instead of polybius (now supported); expected status updated.
- `test_null_baselines.py::test_p_value_gate_suppresses_when_p_above_threshold`: fake `p_value_for_alert` mock updated to accept the new `family=""` kwarg.
- `test_theory_ledger.py::test_approve_novel_theory`: added a minimal grille `dsl_spec` so the theory survives the new Category-A check.
- `test_theory_ledger.py::test_batch_evaluation`: "Claim A" novel-family theory got a minimal identity `dsl_spec`.

---

## 5. Non-regression verification

| Check | Expected | Actual | Match |
|---|---|---|---|
| Core test suite | 1529 passed | 1529 passed | ✓ |
| Kryptosbot test suite | 725 + 23 = 748 | 748 passed | ✓ |
| Self-test K1 | 15 cycles | 15 cycles | ✓ |
| Self-test K2 | 17 cycles | 17 cycles | ✓ |
| Self-test K3 | 9345 cycles | 9345 cycles | ✓ |
| R2-5 real-API K1 test | still passes | (R3-2 does not change kryptos/, self_test/, or panel_cribs; R2-5 test suite passes in same run) | ✓ |
| Phase 3 kernel-overrule battery (35 tests) | still green | all 35 pass in `test_verify_against_kernel_adversarial.py` | ✓ |
| Phase 6 p-value gate | fires on p ≤ 1e-6 | `test_p_value_gate_suppresses_when_p_above_threshold` and neighbours pass | ✓ |

---

## 6. Code footprint

```
 kryptosbot/alerts.py                    |  84 +++++-  (R2-4 matched-null keying)
 kryptosbot/contracts.py                 |  33 +++    (dsl_spec boundary validation)
 kryptosbot/controller.py                | 288 ++++   (new _run_worker + fan-out + prompt)
 kryptosbot/critic.py                    |  73 +++    (Category-A/C check)
 kryptosbot/job_dispatcher.py            |   5 ++    (REJECTED_ADMISSIBILITY mapping)
 kryptosbot/models.py                    |  16 +     (enum + field)
 kryptosbot/null_baselines.py            |  41 +++    (family kwarg on p_value_for_alert)
 kryptosbot/theory_ledger.py             |  32 +++    (dsl_spec column + migration)
 kryptosbot/tests/                       |  +23 test file + 42 lines of updates
 ────────────────────────────────────────
 Production code delta: ~580 lines
```

Brief scope cap was ~800 lines. Landed at 73% of cap — comfortable headroom, no escalation needed. Budget estimate from pre-flight §5 (~320 lines) was low because the `_run_worker` rewrite and the theorist prompt rewrite were both larger than anticipated; neither grew beyond "thin adapter over existing infrastructure" in character.

---

## 7. What this phase did NOT change

- No kernel code (`kryptos/` untouched).
- No self-test code (`kryptosbot/self_test.py` untouched).
- No R2-5 infrastructure (`panel_cribs.py`, `token_accountant.py`).
- No pantheon sibling call architecture.
- No MCP tools added.
- No retirement of `_run_worker_legacy` — still live for Category B.
- No DSL schema changes (`_SUPPORTED_KINDS` still 9 kinds from R3-0.5).
- No theorist persona routing changes (Category-A theories don't use personas because they don't run LLMs; Category-B theories continue to use Day-4 persona selection).

---

## 8. Handoff to R3-3

R3-3's job (integration test) inherits:

- `WorkerStatus.REJECTED_ADMISSIBILITY` available for assertions in mortality-table tests.
- `worker_role` values `"dsl_dispatcher"` / `"agent_sdk_non_dsl_category"` / `"agent_sdk"` distinguishable in mortality telemetry.
- Synthetic-theory test harness surface: `TheoryRecord` with `dsl_spec` → `_dispatch_theories` → contracts with categorizable `worker_role`.
- Alert gate routes through matched-family null when pipeline metadata is present.

R3-3 writes the synthetic-theory integration test covering the brief §4.2 assertions:

- Non-zero D column in mortality table
- Matched-family null consulted at least once
- `override_exhaustion=True` path exercised
- `dsl_untranslatable` critic reject exercised
- Translation error path exercised
- `worker_scratch/` empty after DSL cycle
- Every theory ledgered with `dsl_spec` populated

Plus the real-theorist `--dry-run` spec-production rate measurement on Category A (≥80% floor per brief §0.5 falsification target).

*End of R3-2 phase report.*
