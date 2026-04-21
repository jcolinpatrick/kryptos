# Current Worker Path — Pre-R3 Map

**Phase:** R3-1 audit (no code changes)
**Reference commit:** `e2fbdcc` (HEAD after pre-R3 hygiene fix)
**Purpose:** Precise map of how a proposed theory travels from theorist output to ledger persistence today, with every function, every file, every line number, so R3-2 has an unambiguous target.

---

## 1. Entry point — the call chain

```
ResearchController.run()                                    kryptosbot/controller.py:~430
  → _propose_theories(landscape)                            kryptosbot/controller.py
      → safe_query(prompt=theorist_prompt, options=...)     kryptosbot/sdk_wrapper.py
      → validate_theory_proposals(raw)                      kryptosbot/contracts.py:417
  → critic.evaluate_batch(theories)                         kryptosbot/critic.py:498
  → _red_team_filter(approved)                              kryptosbot/controller.py:555
  → _dispatch_theories(approved)                            kryptosbot/controller.py:1638
      → _run_worker(theory)  (per theory, via asyncio.gather)
          kryptosbot/controller.py:1698
  → _absorb_outcomes(outcomes)                              kryptosbot/controller.py:2353
  → _stat_audit_filter(approved, outcomes)                  kryptosbot/controller.py:2615
  → _run_alerts(approved, outcomes)                         kryptosbot/controller.py:2518
  → _run_lead_pursuit(approved, outcomes)                   kryptosbot/controller.py:2790
  → _update_state_counts()                                  kryptosbot/controller.py
  → ledger.save_controller_state(state)                     kryptosbot/theory_ledger.py
  → _run_synthesis(approved, outcomes)                      kryptosbot/controller.py:2947
```

Full loop source: `kryptosbot/controller.py:540–613`.

### 1.1 The specific path R3-2 rewrites

`_run_worker` at `kryptosbot/controller.py:1698` is the cutover target. Key inner calls:

| Line | Call | Purpose |
|---|---|---|
| 1702 | `async with self._semaphore:` | Concurrency gate |
| 1707 | `worker_role="agent_sdk"` | Hardcoded SDK tag — **R3-2 adds `"dsl_dispatcher"` value** |
| 1718 | `self._worker_scratch_dir(theory)` | Writes `results/worker_scratch/<hid>/` — **R3-2 bypasses on DSL path** |
| 1722 | `self._build_worker_prompt(theory)` | Freeform prompt (see §2) — **R3-2 replaces on DSL path** |
| 1738–1774 | `select_worker(family, roster)` | Day 4 persona routing — **unchanged by R3-2 but the DSL path does not need a persona** |
| 1803 | `options = ClaudeAgentOptions(**options_kwargs)` | SDK options — **R3-2 skips on DSL path** |
| 1844 | `async for message in safe_query(prompt=prompt, options=options):` | SDK subprocess call — **R3-2 replaces with `await asyncio.to_thread(execute, spec)`** |
| 1905 | `validate_worker_contract(raw_output, theory.hypothesis_id)` | Freeform → WorkerContract parse — **R3-2 replaces with `job_result_to_worker_contract()`** |
| 1939 | `self._record_experiment_and_link(exp)` | Persist — **unchanged** |
| 1947 | `self._cleanup_worker_artifacts(theory, contract)` | Scratch cleanup — **unchanged but harmless on DSL path since scratch was never created** |

---

## 2. What the worker receives today

### 2.1 Prompt shape

`_build_worker_prompt` at `kryptosbot/controller.py:2219` builds a freeform prompt containing:

1. Optional **risk warning block** (`_build_risk_warning_block` at line 2113) injected for red-team verdicts with `search_space_risk` in `{unbounded_search, exhausted_source_material, underconstrained}`. Other values dispatch clean.
2. **HYPOTHESIS block** with `hypothesis_id`, `title`, `core_claim`, `mechanism`, `family`, `kill_criteria` (JSON), `expected_signal`, `minimal_test_spec` (JSON).
3. **INSTRUCTIONS** (1–4): use tools → prefer DSL → evaluate → report structured JSON.
4. **DSL-FIRST EXECUTION (PREFERRED PATH, Phase 5)** block at prompt lines 2260–2284 in the source. This section already advertises the DSL: `enumerate_admissible_transforms`, `request_compute_budget_estimate`, `query_exhaustion`, `submit_hypothesis_spec`, `poll_job`, `score_candidate_canonical`.
5. **SCRATCH FILES** directive — worker may only write to `results/worker_scratch/<hid>/`.
6. **OUTPUT CONTRACT** — strict JSON matching `WorkerContract`.

**Critical observation.** The prompt *asks* the worker to prefer the DSL path. But the controller itself never enforces this: the worker is an LLM agent deciding at runtime whether to call `submit_hypothesis_spec` (an MCP tool that invokes `job_dispatcher.execute` via `kryptosbot/dsl_tools.py`) or to fall back to scratch-script execution. The K4 run (2026-04-21) shows 100% fallback to scratch scripts — the postmortem §6.1.6 "Row D = 0" observation.

R3-2 removes the worker's choice: the controller dispatches DSL directly, skipping the agent loop on the DSL path.

### 2.2 Tools the worker has access to

From `kryptosbot/controller.py:1791`:

```python
allowed_tools=self.config.allowed_tools,
permission_mode=self.config.permission_mode,
```

The actual tool list is in `kryptosbot/config.py`; notable DSL tools exposed via MCP:

- `enumerate_admissible_transforms` — lists `_SUPPORTED_KINDS`
- `request_compute_budget_estimate` — wraps `HypothesisSpec.expected_cardinality()`
- `query_exhaustion` — wraps `_exhaustion_overlap`
- `submit_hypothesis_spec` — wraps `execute()`
- `poll_job` — returns `JobResult`
- `score_candidate_canonical` — wraps `kryptos.kernel.scoring.aggregate.score_candidate`

These live in `kryptosbot/dsl_tools.py`. Under R3-2 they remain available to fallback (legacy) workers, but the DSL path never spins up a worker so these tools go unused during DSL dispatch.

### 2.3 Scratch directory convention

`_worker_scratch_dir(theory)` at `kryptosbot/controller.py:2097` returns:

```
<project_root>/results/worker_scratch/<theory.hypothesis_id>/
```

Created in `_run_worker` at line 1718, removed in `_cleanup_worker_artifacts` at line 1947 (pass 1 removes the directory, pass 2 defensively scans `scripts/`, `tests/`, `src/` for files whose name contains the `hypothesis_id[:12]` prefix or recently-modified files that mention it).

Under R3-2's DSL path, the scratch directory is NEVER created. The cleanup pass still runs but is a no-op. Artifacts live instead at:

```
<project_root>/results/dsl_jobs/<hypothesis_id>_<spec_hash>/result.json
```

as written by `job_dispatcher.execute()` at `kryptosbot/job_dispatcher.py:694`.

---

## 3. What the worker returns today

### 3.1 Raw shape

The worker's stdout is collected by `_run_worker` into `raw_chunks: list[str]` (line 1805) and joined into `raw_output` (line 1902). That raw string is then parsed into a `WorkerContract`.

### 3.2 `WorkerContract` schema

Defined at `kryptosbot/models.py:225` (full struct). Fields by trust level:

**Kernel-verified (Phase 3 overrule — trusted):**
- `crib_score: int`
- `bean_passed: bool`
- `score: float` — a mirror of `crib_score` after overrule
- `bean_variant: Optional[str]` — which additive variant passed

**Worker-self-reported (informational only, never drives control flow):**
- `status: WorkerStatus` (SUCCESS, DISPROVED, INCONCLUSIVE, ERROR, TIMEOUT)
- `best_plaintext: str`
- `disproof_evidence: list[str]`
- `supporting_evidence: list[str]`
- `next_action: str`
- `family_generalization: str`
- `narrative_summary: str`
- `raw_artifacts: dict`

**Controller-populated (post-parse):**
- `worker_role: str` (currently always `"agent_sdk"`, becomes `"dsl_dispatcher"` on DSL path)
- `duration_seconds: float`
- `fields_overwritten: bool` (Phase 3)
- `worker_self_report: dict` (Phase 3 — what the worker tried to claim before overrule)
- `verification_error: str` (Phase 3)

### 3.3 Parse flow

`validate_worker_contract(raw_output, hypothesis_id)` at `kryptosbot/contracts.py` extracts the JSON from `raw_output`, runs `WorkerContract.validated_from_dict`, then calls `_verify_against_kernel(contract)` at line 81 of contracts.py. The verifier:

- Recomputes `crib_score` and `bean_passed` from `best_plaintext` using `kryptos.kernel.scoring.aggregate.score_candidate`.
- Overwrites the worker's self-reported values with kernel values.
- Sets `fields_overwritten=True`, preserves the worker's original attempt in `worker_self_report`.

Under the DSL path, the equivalent kernel-overrule happens inside `job_result_to_worker_contract()` at `kryptosbot/job_dispatcher.py:853` (`_verify_against_kernel(contract)` call). Semantics are identical — the overrule is applied once before the contract is returned to `_run_worker`, and the caller never sees an un-overruled contract.

---

## 4. Where Round 2 components connect

For each R2 component, the file + line where it *should* fire under R3 but currently doesn't. Marked "new call site" where R3-2 must add a call rather than redirecting an existing one.

### 4.1 R2-1: double-columnar strategy in self-test

**File:** `kryptosbot/self_test.py::_columnar_double_candidates` (separate from the live controller).

**Status:** Already live in the self-test harness. Verified by pre-flight §1.5 (K3/9345 discovered via `columnar_double`). **No R3 wiring required** — R2-1 is a self-test-only component.

### 4.2 R2-2: KA + keyword_mixed alphabets in `_translate_layer`

**File:** `kryptosbot/job_dispatcher.py:371`.

**Where it should fire:** inside `job_dispatcher.execute()`, called from the new `_run_worker` DSL path.

**Current state:** fires only when an MCP tool invokes `submit_hypothesis_spec` during a worker's self-directed DSL use — which the 2026-04-21 K4 run did not. Under R3-2, it fires on **every** theory the controller dispatches (via `await asyncio.to_thread(execute, spec)` at the new `_run_worker`).

**No new call site needed.** R3-2 just routes control into the existing call.

### 4.3 R2-3: exhaustion-overlap override + critic duplicate guard

**File (admissibility):** `kryptosbot/job_dispatcher.py::check_admissibility` lines 148–213. Override branch at 196–203.

**File (critic duplicate guard):** `kryptosbot/critic.py::_check_override_duplicate` line 508.

**Status:**
- **Critic duplicate guard** — already fires, before R3. Runs at `kryptosbot/critic.py:414` during every theorist cycle. R3-2 does not touch this.
- **Admissibility override branch** — only fires if `check_admissibility` is called with a spec carrying `override_exhaustion=True`. Today the controller never calls `check_admissibility`. Under R3-2, every DSL dispatch runs through it, so the override branch will fire whenever a theorist's spec carries the flag.

**No new call site needed.** R3-2 just wires `check_admissibility` into `_run_worker`.

### 4.4 R2-4: matched-family nulls (columnar_single / columnar_double / beaufort / variant_beaufort)

**File (calibration):** `kryptosbot/null_baselines.py` + `null_baselines/manifest.json`.

**File (consumption in alerts):** `kryptosbot/alerts.py` + `kryptosbot/controller.py::_run_alerts` at line 2518.

**Current state:** alert gate falls back to `random_text` when no family-specific null is cached. R3-2 makes this consultation non-trivial by feeding the alert gate a `WorkerContract` that carries enough family signal to do matched-null lookup.

**Where the lookup happens:** `_run_alerts` passes each `WorkerContract` through stat-audit and null-baseline lookup. The current (pre-R3) logic keys on `theory.family` to pick a null family. Under R3-2, the DSL `HypothesisSpec.pipeline[0].kind` is a more reliable family signal than `theory.family` (which is theorist-declared free-form). **R3-2 should ensure the contract's `raw_artifacts["job_result"]` preserves the spec hash + layer kinds so `_run_alerts` can match a family null precisely.**

This is the one place R3-2 needs to touch *downstream* code. Likely change in `_run_alerts` / `alerts.py`: key the matched-null lookup on `raw_artifacts["spec"]["pipeline"][0]["kind"]` when present, else fall back to the legacy `theory.family` heuristic.

### 4.5 R2-5: `PanelCribs` + `TokenAccountant`

**File:** `kryptosbot/panel_cribs.py`, `kryptosbot/token_accountant.py`, plus integration in `kryptosbot/self_test.py` and the direct-API loop-lite.

**Status:** these are infrastructure for the self-test's K1 real-API pass. **Not in the live controller's path** — their role is confirmed by R2-5's separate real-API test, not by the live run. R3-2 does not touch them.

`TokenAccountant` is referenced in brief §3.7 as "sitting idle" during the 2026-04-21 K4 run because tokens on the worker path are now irrelevant (workers don't call Claude on the DSL path). R3 does not integrate `TokenAccountant` into the controller; that's a later round's concern.

---

## 5. Orphan paths

Functions that exist in the codebase, appear designed for the DSL dispatch flow, but are never called by the controller today:

### 5.1 `kryptosbot/job_dispatcher.py::execute`

**Line:** 589.
**Callers today:** `kryptosbot/dsl_tools.py::submit_hypothesis_spec` (MCP tool, invoked from worker LLM if the worker chooses). Unit tests. No controller code.
**R3-2 makes it:** the primary mechanism for dispatching every approved theory.

### 5.2 `kryptosbot/job_dispatcher.py::check_admissibility`

**Line:** 148.
**Callers today:** called by `execute()` (line 617). Also by MCP wrappers in `dsl_tools.py`. No controller code.
**R3-2 makes it:** called from the new `_run_worker` *before* dispatch, so the controller can distinguish admissibility-reject from execution-runs-clean in the mortality telemetry.

### 5.3 `kryptosbot/job_dispatcher.py::job_result_to_worker_contract`

**Line:** 764. Docstring explicitly labels this "Phase 4 minimal integration helper. A future session can wire this into the controller's dispatch flow."
**Callers today:** `kryptosbot/dsl_tools.py::poll_job` (returns either `JobResult` or the derived `WorkerContract`). Tests. No controller code.
**R3-2 makes it:** called from the new `_run_worker` to convert `JobResult` → `WorkerContract` after a successful dispatch.

### 5.4 `kryptosbot/hypothesis_dsl.py::validate_hypothesis_spec`

**Line:** 512.
**Callers today:** `execute_from_json()` at 857. `dsl_tools.py` MCP tools. Tests. No controller code.
**R3-2 makes it:** called from `contracts.validate_theory_proposals` when parsing the theorist's output, so an invalid `dsl_spec` is caught before a `TheoryRecord` is constructed.

### 5.5 `kryptosbot/contracts.py::_verify_against_kernel`

**Line:** 81.
**Callers today:** `validate_worker_contract` (parses freeform SDK worker output). `job_result_to_worker_contract` (the orphan above). Direct tests.
**R3-2 touches:** unchanged. Already covers both paths.

---

## 6. Existing guards that R3-2 must preserve

These are Phase 3 / R2 guarantees that the new dispatch path must not break:

1. **Kernel overrule.** Every `WorkerContract` returned from `_run_worker` must have passed through `_verify_against_kernel`. The DSL path satisfies this via `job_result_to_worker_contract` (line 853). R3-2 tests should assert `fields_overwritten=True` on any DSL-produced contract whose `best_plaintext` is a 97-char string.

2. **Override-justification duplicate guard.** `critic._check_override_duplicate` runs at every critic pass. R3-2 does not touch it, but R3-3 synthetic tests must cover the path that (a) a theorist emits `override_exhaustion=True` with a non-empty justification, (b) the critic passes it, (c) the dispatcher honors it.

3. **p-value gate (Phase 6).** `_run_alerts` gates on `p_value_vs_null <= 1e-6` in addition to crib_score. If the DSL `JobResult` doesn't populate `best_p_value_vs_null` (Phase 4 comment at `job_dispatcher.py:89` says "populated in Phase 6"), the gate fails open to legacy crib-only gating with a WARNING. R3-2 does not need to populate the field; R3-3 must assert the gate's fail-open WARNING is emitted when appropriate.

4. **Cleanup pass.** `_cleanup_worker_artifacts` at line 1961 scans `scripts/`/`tests/`/`src/` for violations. Even under the DSL path where no worker could have written there, this pass should still run as defense-in-depth. R3-2 keeps the call; it should be a no-op.

5. **Exception path.** `_dispatch_theories` at line 1659 uses `asyncio.gather(return_exceptions=True)`, constructs an `ERROR` contract for any raised exception, and persists the experiment. R3-2 preserves this. A DSL-path exception (e.g., `DispatcherError` from an untranslatable layer that slipped past critic) produces an `ERROR` contract with the exception type + message.

---

## 7. Ledger persistence notes

`TheoryRecord` at `kryptosbot/models.py:104` does **not** currently have a top-level `dsl_spec` field. The theorist's `dsl_spec` (when the prompt asks for one) would have to live inside `minimal_test_spec: dict[str, Any]`. R3-2 adds a dedicated `dsl_spec: dict = field(default_factory=dict)` field to `TheoryRecord` so:

- The controller can fetch `theory.dsl_spec` without dict-key archaeology.
- The ledger SQLite schema gets a new column or stores it in the existing `notes` blob (decision deferred to DSL_CUTOVER_CONTRACT.md §5).
- R3-3 assertion `every theory has dsl_spec populated` becomes a single attribute lookup.

---

## 8. Summary of what changes and what doesn't

**Changes (R3-2):**

- `TheoryRecord` gains `dsl_spec: dict` field.
- `WorkerStatus` gains `REJECTED_ADMISSIBILITY` value.
- `validate_theory_proposals` parses + validates `dsl_spec`; invalid specs land in `TheoryParseReport.invalid`.
- `TheoryCritic.evaluate` gets a new early check: empty-spec theories get `REJECT_UNDERCONSTRAINED` with reason `"dsl_untranslatable"`.
- `_run_worker` rewrites per DSL_CUTOVER_CONTRACT §2.2 pseudo-code. Legacy path kept as `_run_worker_legacy` with `DeprecationWarning`.
- `_build_worker_prompt` unchanged but only used by `_run_worker_legacy`.
- `_build_theorist_prompt` updated to require `dsl_spec` in every proposal and to document the `dsl_untranslatable` fallback.
- `_run_alerts` / `alerts.py` tweaked to prefer spec-derived family over theorist-declared family for matched-null lookup.

**Unchanged (R3-2 explicitly preserves):**

- Everything in `kryptos/` (core library).
- All self-test code — `_columnar_double_candidates` stays exactly as-is per brief §6.3.
- All Phase 3 kernel-overrule logic.
- Critic's duplicate, retired-palette, CONSENSUS_NULL_POSITIONS, family-tier, contradictions, override-duplicate, prompt-surface-scope checks.
- All sibling calls: red-team precheck, stat-audit filter, lead-pursuit, synthesis.
- `_absorb_outcomes`, `_record_experiment_and_link`.
- `_cleanup_worker_artifacts` (called, but usually no-op on DSL path).
- Ledger schemas except the new `dsl_spec` column.

---

*End of CURRENT_WORKER_PATH.md. Companion document: DSL_CUTOVER_CONTRACT.md — specifies exactly what R3-2 implements.*
