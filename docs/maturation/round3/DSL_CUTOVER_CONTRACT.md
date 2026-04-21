# DSL Cutover Contract — R3-2 Implementation Target

**Phase:** R3-1 design (no code changes)
**Consumer:** Phase R3-2 implementation
**Purpose:** Specify exactly what R3-2 implements, in enough detail that R3-2 needs no further design decisions.

---

## 1. Theorist output contract

### 1.1 New required field: `dsl_spec`

The theorist prompt currently lists `"dsl_spec": null` as an **optional** JSON field (see `kryptosbot/controller.py:1557`, and the explanatory block at 1561–1567: "Phase 4 accepts null here; leave null when no clean DSL translation exists"). R3-2 makes it **required**.

Every theory proposal must include a `dsl_spec` field that is either:

- A JSON object conforming to `kryptosbot.hypothesis_dsl.HypothesisSpec.to_dict()` — a computable specification; OR
- The literal `null` — an explicit statement that no DSL translation exists.

Ambiguous values (missing field, empty object `{}`, empty string) cause the theory to land in `TheoryParseReport.invalid` with reason `"dsl_spec must be a HypothesisSpec object or null"`.

### 1.2 Supported cipher kinds (as of R3 entry)

Only theories whose `dsl_spec.pipeline[*].kind` values are all in `kryptosbot.job_dispatcher._SUPPORTED_KINDS` will pass the new critic check:

```
identity, vigenere, beaufort, variant_beaufort, columnar, atbash
```

Kinds present in the DSL type literal but **not** currently translatable by the dispatcher:

```
rail_fence, route, myszkowski, polybius, quagmire, procedural
```

Theories whose pipeline includes any of the second list will be rejected by the critic with reason `"dsl_untranslatable: kind <X> has no dispatcher translation (R3 scope; extending DSL is a later brief)"`.

This is a deliberate consequence of brief §6.1 ("Do not expand the DSL") and §policy. Growing `_SUPPORTED_KINDS` is its own brief; R3 wires what exists.

### 1.3 Worked examples

Three examples the theorist prompt will include verbatim (see §3.1 for the prompt edit).

#### Example A — Single-layer Vigenère on the KRYPTOS alphabet

Theorist's natural-language hypothesis: *"K4 uses a simple Vigenère cipher with the KRYPTOS-keyword-mixed alphabet (as in K1 and K2), with keyword in a small enumerated set of thematic candidates."*

```json
{
  "hypothesis_id": "<filled by controller from core_claim>",
  "pipeline": [
    {
      "kind": "vigenere",
      "alphabet": "KA",
      "params": [
        {"name": "keyword", "values": ["PALIMPSEST", "ABSCISSA", "KRYPTOS", "SANBORN"]}
      ]
    }
  ],
  "crib_alignment": "direct_positional",
  "scoring": "crib_plus_bean",
  "compute_budget_cpu_minutes": 1,
  "assumption_bundle": ["single_layer", "H1_direct_positional", "alphabet_KA"],
  "kill_criteria": {
    "max_crib_score": 5,
    "bean_passed": false
  },
  "success_criteria": {
    "crib_score": 18,
    "bean_passed": true
  },
  "notes": "K1/K2 rediscovered via this exact configuration; check whether the KA alphabet extends to K4."
}
```

Cardinality: 4. Budget: 1 CPU-min × 200_000 = 200K — trivially within budget.

#### Example B — Two-layer columnar-then-Vigenère

Theorist's natural-language hypothesis: *"K4 is a columnar transposition (width=7) applied to a Vigenère ciphertext with keyword 'KRYPTOS'."*

```json
{
  "hypothesis_id": "<filled by controller from core_claim>",
  "pipeline": [
    {
      "kind": "columnar",
      "alphabet": "AZ",
      "params": [
        {"name": "width", "values": [7]},
        {"name": "col_order", "values": [
          [0, 1, 2, 3, 4, 5, 6],
          [6, 5, 4, 3, 2, 1, 0],
          [3, 1, 4, 0, 6, 2, 5]
        ]}
      ]
    },
    {
      "kind": "vigenere",
      "alphabet": "AZ",
      "params": [
        {"name": "keyword", "values": ["KRYPTOS", "BERLIN", "PALIMPSEST"]}
      ]
    }
  ],
  "crib_alignment": "post_transposition",
  "scoring": "crib_plus_bean",
  "compute_budget_cpu_minutes": 2,
  "assumption_bundle": ["multilayer", "columnar_first", "peel_order_tv"],
  "kill_criteria": {
    "max_crib_score": 5
  },
  "notes": "Tests specific columnar orders against thematic Vigenère keywords."
}
```

Cardinality: 3 (col_orders) × 3 (keywords) = 9 configs. Budget check trivially passes.

Post-transposition crib alignment is already supported by the dispatcher's kernel path because `build_pipeline` handles multi-step compositions; crib scoring always runs on the final plaintext.

#### Example C — Untranslatable hypothesis (honest rejection)

Theorist's natural-language hypothesis: *"K4 uses the P-F1-1 procedural recipe — reverse the ciphertext, then apply a Polybius 5×5 substitution from the KRYPTOS tableau."*

```json
{
  "hypothesis_id": "<filled by controller from core_claim>",
  "dsl_spec": null,
  "core_claim": "...",
  "mechanism": "Procedural recipe P-F1-1 applied to K4",
  "notes": "DSL cannot express procedural recipes yet — rail_fence, polybius, procedural, route, myszkowski, and quagmire kinds lack dispatcher translations in R3."
}
```

**Outcome:** critic rejects with `CriticDecision.REJECT_UNDERCONSTRAINED`, reason `"dsl_untranslatable: theorist declared dsl_spec=null; DSL does not cover this hypothesis in R3"`.

This is the correct behaviour per brief §6.1. Under the brief's scope discipline, DSL growth is deferred. R3-3's real-theorist test must demonstrate that the theorist proposes translatable hypotheses at least 80% of the time so this rejection path is exercised but not dominant.

### 1.4 Validation order

`validate_theory_proposals` at `kryptosbot/contracts.py:417` runs these checks in order (new step bolded):

1. Extract JSON array from raw theorist output.
2. Each item has the required string fields (`title`, `core_claim`, `mechanism`, `family`).
3. List fields are lists.
4. `anomalies_exploited` entries are canonical anomaly_ids.
5. `minimal_test_spec` is a dict (optional).
6. **NEW: `dsl_spec` is either a dict or literal `null`. If dict, `validate_hypothesis_spec(dsl_spec)` must succeed. If validation fails, theory goes to `invalid` with the full validation errors concatenated into the reason string.**
7. Construct `TheoryRecord` with the new `dsl_spec` attribute populated (`dict` for success, `{}` for null / absent).

---

## 2. Fallback policy: FB-1 (reject at critic)

The brief proposes three fallback options:

- **FB-1** — Reject at critic with `CriticDecision.REJECT_UNDERCONSTRAINED` sub-reason `"dsl_untranslatable"`. Theorist must re-propose.
- **FB-2** — Route untranslatable theories through the legacy freeform-worker path with explicit ledger tagging.
- **FB-3** — Downgrade to `INCONCLUSIVE` at dispatch time with reason `"no valid DSL translation"`.

**Decision: FB-1.**

Rationale:

1. **Matches brief default recommendation.** §2.2 of the brief explicitly recommends FB-1.
2. **Epistemic posture.** FB-1 forces theorists to propose what the framework can actually test. FB-2 preserves a parallel freeform path indefinitely; FB-3 burns an admissibility cycle on a guaranteed-fail theory.
3. **Scope discipline.** FB-1 closes the pre-R3 gap cleanly. FB-2 would require retaining and maintaining the legacy SDK-worker prompt for another round with no new falsifiable requirement on it.
4. **Token economy.** A single FB-1 rejection costs zero tokens beyond the critic's existing run. FB-2 would spend a full worker's subscription turn on a theory the DSL can't handle.

**Implications for R3-3:**

- Mortality telemetry will have a new row: `critic reject_underconstrained: dsl_untranslatable`.
- Theorist prompt iteration (R3-3 §4.4) is the main gate: if >20% of real-theorist proposals hit FB-1, the prompt needs tightening. Persistent failure to hit the 80% target is an R3 stop condition.

---

## 3. The new `_run_worker` — pseudo-code

```python
async def _run_worker(
    self, theory: TheoryRecord, on_message: Any = None,
) -> WorkerContract:
    """Dispatch one theory via the DSL. No Claude call on this path.

    R3-2 (2026-04-21): this replaces the pre-R3 SDK-subprocess path.
    The old path is preserved as _run_worker_legacy with DeprecationWarning
    and is only reachable via explicit opt-in (not used by the controller).
    """
    async with self._semaphore:
        exp_id = f"exp-{uuid.uuid4().hex[:8]}"
        exp = ExperimentRecord(
            experiment_id=exp_id,
            hypothesis_id=theory.hypothesis_id,
            worker_role="dsl_dispatcher",
            config=theory.dsl_spec,
        )
        start_time = datetime.now(timezone.utc)
        if on_message:
            on_message(theory.hypothesis_id, "start", theory.title)

        # Step 1: Parse the DSL spec. Invariant: by this point the critic
        # has already accepted the spec, so this should never fail.
        # If it does, treat as an ERROR contract.
        try:
            spec = HypothesisSpec.from_dict(theory.dsl_spec)
            spec_errors = spec.validate()
            if spec_errors:
                raise ValueError(f"Spec revalidation failed: {spec_errors}")
        except Exception as exc:
            contract = WorkerContract(
                hypothesis_id=theory.hypothesis_id,
                worker_role="dsl_dispatcher",
                status=WorkerStatus.ERROR,
                error=f"Spec parse failure (post-critic): {exc}",
                duration_seconds=(datetime.now(timezone.utc) - start_time).total_seconds(),
            )
            exp.completed_at = _now_iso()
            exp.result = contract
            self._record_experiment_and_link(exp)
            return contract

        # Step 2: Admissibility check. If rejected, return immediately —
        # no compute spent. This is the path the K4 2026-04-21 run never
        # reached; the mortality table's D column starts populating here.
        admissible, reasons = check_admissibility(spec)
        if not admissible:
            contract = WorkerContract(
                hypothesis_id=theory.hypothesis_id,
                worker_role="dsl_dispatcher",
                status=WorkerStatus.REJECTED_ADMISSIBILITY,
                disproof_evidence=[f"ADMISSIBILITY: {r}" for r in reasons],
                duration_seconds=(datetime.now(timezone.utc) - start_time).total_seconds(),
                narrative_summary=(
                    f"Admissibility check rejected the spec without running compute. "
                    f"{len(reasons)} reason(s)."
                ),
            )
            if on_message:
                on_message(
                    theory.hypothesis_id, "done",
                    f"rejected_admissibility: {len(reasons)} reason(s)",
                )
            exp.completed_at = _now_iso()
            exp.result = contract
            self._record_experiment_and_link(exp)
            return contract

        # Step 3: Dispatch via multiprocessing Pool inside job_dispatcher.
        # asyncio.to_thread so the controller's event loop stays responsive
        # while the dispatcher runs sync multiprocessing. The dispatcher
        # handles its own Pool(cpu_count()-2).
        if on_message:
            on_message(
                theory.hypothesis_id, "dispatch",
                f"running {spec.expected_cardinality()} configs",
            )
        job_result = await asyncio.to_thread(execute, spec)
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        # Step 4: Convert to WorkerContract — kernel overrule happens here
        # (job_result_to_worker_contract calls _verify_against_kernel).
        contract = job_result_to_worker_contract(
            job_result, hypothesis_id=theory.hypothesis_id,
        )
        contract.duration_seconds = elapsed
        contract.worker_role = "dsl_dispatcher"  # overwrite in case helper drifts

        # Step 5: For alert-path matched-null lookup, preserve the pipeline
        # layer kinds in raw_artifacts so _run_alerts can key off them
        # (R2-4 integration). The JobResult already carries the spec via
        # artifact_path; here we denormalize just the kinds for fast lookup.
        contract.raw_artifacts.setdefault("dsl_pipeline_kinds", [
            layer.kind for layer in spec.pipeline
        ])
        contract.raw_artifacts.setdefault("dsl_spec_hash", spec.spec_hash)

        if on_message:
            on_message(
                theory.hypothesis_id, "done",
                f"{contract.status.value} score={contract.score} in {elapsed:.0f}s",
            )

        # Step 6: Persist experiment + best-effort scratch cleanup
        # (no-op on DSL path; defense-in-depth only).
        exp.completed_at = _now_iso()
        exp.result = contract
        self._record_experiment_and_link(exp)
        self._cleanup_worker_artifacts(theory, contract)
        return contract
```

**Key invariants:**

- **No Claude call on this path.** The `safe_query` / `ClaudeAgentOptions` / `async for message` triad is entirely gone from `_run_worker`. Tokens on the worker path drop to zero.
- **No scratch directory created.** `_worker_scratch_dir` is not called; `results/worker_scratch/<hid>/` is never produced. Artifacts live at `results/dsl_jobs/<hypothesis_id>_<spec_hash>/result.json` (written by `execute()`).
- **Kernel overrule preserved.** `job_result_to_worker_contract` calls `_verify_against_kernel` internally (`kryptosbot/job_dispatcher.py:853`).
- **Persona routing bypassed.** No `select_worker` call, no `worker_system_prompt()`, no `setting_sources` — those are SDK concepts that don't apply when there's no SDK call.
- **Exception path unchanged.** `_dispatch_theories` at line 1659 still uses `return_exceptions=True`; any exception from the new `_run_worker` is caught at the gather boundary and turned into an ERROR contract.

---

## 4. `WorkerStatus` enum additions

### 4.1 New value

```python
class WorkerStatus(str, Enum):
    SUCCESS = "success"
    DISPROVED = "disproved"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    TIMEOUT = "timeout"
    REJECTED_ADMISSIBILITY = "rejected_admissibility"  # NEW in R3-2
```

### 4.2 Semantics of `REJECTED_ADMISSIBILITY`

Distinct from the four existing statuses:

- **vs INCONCLUSIVE:** INCONCLUSIVE means the dispatch ran but nothing was stored (crib_score < STORE_THRESHOLD on all configs). REJECTED_ADMISSIBILITY means no compute was spent — the spec was rejected before dispatch.
- **vs ERROR:** ERROR means the dispatch raised an exception. REJECTED_ADMISSIBILITY means the admissibility check returned `admissible=False` cleanly.
- **vs DISPROVED:** DISPROVED means the spec ran to completion with an eliminated_claim populated. REJECTED_ADMISSIBILITY means the spec never ran.

### 4.3 Contract shape under REJECTED_ADMISSIBILITY

```python
WorkerContract(
    hypothesis_id=...,
    worker_role="dsl_dispatcher",
    status=WorkerStatus.REJECTED_ADMISSIBILITY,
    score=0.0,
    crib_score=0,
    bean_passed=False,
    best_plaintext="",
    disproof_evidence=[
        "ADMISSIBILITY: <reason 1>",
        "ADMISSIBILITY: <reason 2>",
        ...
    ],
    supporting_evidence=[],
    next_action="",
    family_generalization="",
    raw_artifacts={
        "dsl_spec_hash": spec.spec_hash,
        "dsl_pipeline_kinds": [...],
    },
    duration_seconds=<small; admissibility is fast>,
    error="",
    narrative_summary="Admissibility check rejected the spec without running compute. N reason(s).",
    fields_overwritten=False,
    worker_self_report={},
    verification_error="",
    bean_variant=None,
)
```

### 4.4 Update to `job_result_to_worker_contract`

Currently at `kryptosbot/job_dispatcher.py:796`:

```python
if result.admissibility_verdict == "rejected":
    status = WorkerStatus.INCONCLUSIVE  # <-- will change to REJECTED_ADMISSIBILITY
```

R3-2 changes the above to `WorkerStatus.REJECTED_ADMISSIBILITY`. This ensures the helper's behaviour matches the new enum.

### 4.5 Downstream consumer updates

- `_absorb_outcomes` (line 2353): treat REJECTED_ADMISSIBILITY like INCONCLUSIVE for ledger status — theory goes to `TheoryStatus.COMPLETED` with `best_score=0`. Verify no alert-on-signal path fires (it shouldn't; score=0).
- `_run_alerts` (line 2518): REJECTED_ADMISSIBILITY never triggers a signal alert. No change needed beyond confirming the gate's existing logic.
- `_stat_audit_filter` (line 2615): skip REJECTED_ADMISSIBILITY entries from audit (no compute to audit).
- `_run_lead_pursuit` (line 2790): skip REJECTED_ADMISSIBILITY (no crib_score signal).
- `_run_synthesis` (line 2947): include REJECTED_ADMISSIBILITY in cycle summary counts but not in "tested" counts.

R3-2 implementation tests these explicitly in the 12-test pack (brief §3.8).

---

## 5. Ledger / `TheoryRecord` schema changes

### 5.1 New field on `TheoryRecord`

```python
@dataclass
class TheoryRecord:
    ...existing fields...
    dsl_spec: dict[str, Any] = field(default_factory=dict)  # NEW in R3-2
```

The stored value is either a `HypothesisSpec.to_dict()` output (dict) or `{}` (explicit-null or absent).

### 5.2 SQLite schema update

`kryptosbot/theory_ledger.py` (or equivalent storage layer) persists `TheoryRecord`. R3-2 adds:

- Either: a new SQLite column `dsl_spec TEXT` storing `json.dumps(theory.dsl_spec)` (or `NULL` when empty).
- Or: serialize the field inside the existing `notes` or similar blob column.

Decision: **new dedicated column.** Keeping `dsl_spec` separate from `notes` keeps the ledger analytically queryable (e.g., "all theories whose spec has a columnar layer"). Schema migration is a one-time `ALTER TABLE` at ledger initialization; no risk under R3-3's clean-DB test.

### 5.3 TheoryRecord serialization

- `to_dict()` includes `dsl_spec` in the emitted dict.
- `from_dict()` reads `d.get("dsl_spec", {})`. Theories loaded from pre-R3 ledgers lack the field and land with `{}` — correct, since they predate the DSL requirement.

### 5.4 No migration script needed

Pre-R3 theory rows with absent `dsl_spec` load as `dsl_spec={}` — equivalent to "theorist declared dsl_spec=null." These rows are historical records of theories that were tested under the legacy SDK-worker path; they continue to load correctly for audit purposes. No new dispatch decisions are made on pre-R3 rows.

---

## 6. Backward compatibility

### 6.1 Legacy path retention

R3-2 keeps `_run_worker_legacy` importable:

```python
async def _run_worker_legacy(
    self, theory: TheoryRecord, on_message: Any = None,
) -> WorkerContract:
    """Pre-R3 SDK-subprocess worker path. DEPRECATED in R3; will be
    removed in R4 after one round of production confirms nothing
    silently depends on it.
    """
    import warnings
    warnings.warn(
        "_run_worker_legacy is deprecated as of R3; the controller now "
        "dispatches all theories through job_dispatcher.execute. This "
        "path will be removed in R4.",
        DeprecationWarning,
        stacklevel=2,
    )
    # ... existing pre-R3 body unchanged ...
```

The legacy path is not called by `_dispatch_theories`, which unconditionally invokes the new `_run_worker`. Callers outside the controller (tests, one-off scripts) who explicitly want the SDK path must import and call `_run_worker_legacy` directly.

### 6.2 Test compatibility

Tests that previously exercised the SDK-subprocess path are wrapped:

```python
with pytest.deprecated_call():
    contract = await controller._run_worker_legacy(theory)
```

This keeps the legacy tests green while making the deprecation visible.

### 6.3 `_build_worker_prompt` preservation

`_build_worker_prompt` at line 2219 is called only by `_run_worker_legacy`. It stays intact in the source. It is NOT called by the new `_run_worker`. The prompt's "DSL-FIRST EXECUTION" section (lines 2260–2284) becomes vestigial — the only workers that still read this prompt are running through `_run_worker_legacy`, which is deprecated and not reached by the controller.

### 6.4 Theorist prompt edits

`_build_theorist_prompt`:

- Remove the phrase "`dsl_spec` is OPTIONAL" and the `"dsl_spec": null` default.
- Replace with: `"dsl_spec" must be either a HypothesisSpec object or explicit null; absent/empty specs are rejected.`
- Inject the three examples from §1.3 verbatim.
- Add the supported-kinds list from §1.2 with the warning that other kinds will be rejected.
- Keep the existing R2-3 override-exhaustion block (line 1460) unchanged. The override lives on `HypothesisSpec.override_exhaustion`/`override_justification` (already wired); theorists continue to populate it on their specs.

### 6.5 Critic prompt changes

The deterministic critic (`kryptosbot/critic.py`) has no LLM prompt. R3-2's addition is a new early code check in `TheoryCritic.evaluate`:

```python
# --- Check 0 (R3-2): DSL translatability ---
if not theory.dsl_spec:
    return CriticVerdict(
        decision=CriticDecision.REJECT_UNDERCONSTRAINED,
        confidence=1.0,
        reasons=["dsl_untranslatable: theorist declared dsl_spec=null; DSL does not cover this hypothesis in R3"],
    )
from .hypothesis_dsl import HypothesisSpec, validate_hypothesis_spec
from .job_dispatcher import _kind_has_translation, _SUPPORTED_KINDS

parsed = validate_hypothesis_spec(theory.dsl_spec)
if not parsed.is_valid:
    return CriticVerdict(
        decision=CriticDecision.REJECT_UNDERCONSTRAINED,
        confidence=1.0,
        reasons=[
            "dsl_spec failed validation:",
            *parsed.errors,
        ],
    )
spec = parsed.value
untranslatable = [
    layer.kind for layer in spec.pipeline
    if not _kind_has_translation(layer.kind)
]
if untranslatable:
    return CriticVerdict(
        decision=CriticDecision.REJECT_UNDERCONSTRAINED,
        confidence=1.0,
        reasons=[
            f"dsl_untranslatable: kinds {untranslatable} have no dispatcher "
            f"translation (R3 scope; supported: {sorted(_SUPPORTED_KINDS)})",
        ],
    )
# Fall through to existing checks (completeness, family-elimination, ...).
```

The existing R2-3 override-duplicate check at `_check_override_duplicate` (line 508) stays. It is now defense-in-depth: the dispatcher's admissibility check also enforces override semantics at spec level.

---

## 7. Alert-path integration (R2-4 wiring)

### 7.1 Current alert gate

`_run_alerts` at `kryptosbot/controller.py:2518` calls into `kryptosbot/alerts.py` which looks up a null distribution by family label. R2-4 calibrated 6 new matched-family nulls (beaufort, variant_beaufort, columnar_single, columnar_double). Before R3, alerts fall back to `random_text` because the controller's family label isn't always precise.

### 7.2 New keying logic

Under R3-2, a `WorkerContract` from the DSL path carries `raw_artifacts["dsl_pipeline_kinds"]` (per §3 pseudo-code step 5). The alert path prefers:

```python
def _matched_null_family(contract: WorkerContract, theory: TheoryRecord) -> str:
    """Key for matched-null lookup."""
    kinds = contract.raw_artifacts.get("dsl_pipeline_kinds") or []
    if len(kinds) == 1:
        return kinds[0]                          # e.g., "beaufort"
    if len(kinds) == 2 and kinds[0] == "columnar" and kinds[1] == "columnar":
        return "columnar_double"
    if len(kinds) == 1 and kinds[0] == "columnar":
        return "columnar_single"
    return theory.family or ""                   # fallback to theorist-declared family
```

If the resolved family has no calibrated null in `null_baselines/manifest.json`, `_run_alerts` falls back to `random_text` **with a WARNING** (per Phase 6 fail-open semantics in CLAUDE.md). The warning is the telemetry signal that operator wants per R3-4 §5.1-4.

### 7.3 Test assertions (R3-2 and R3-3)

- R3-2: unit test — a WorkerContract with `dsl_pipeline_kinds=["columnar", "columnar"]` resolves to `"columnar_double"`, and the alert gate consults that null entry (mock the manifest).
- R3-3: integration test — a synthetic two-layer columnar theory triggers the matched null, not `random_text`. Verify via log line or spy.

---

## 8. What R3-2 does NOT change

For avoidance of doubt:

- `kernel/` — untouched.
- `kryptosbot/self_test.py` — untouched. Self-test is independent fitness verification.
- `kryptosbot/panel_cribs.py`, `kryptosbot/token_accountant.py` — R2-5 infrastructure; not wired to the live controller in R3. A later round handles.
- Day-4 persona routing for theorists, critics, red-team, stat-audit, lead-pursuit, synthesis — untouched. Only the worker path changes; workers on the DSL path no longer use personas because they no longer run LLMs.
- Pantheon sibling call architecture — untouched.
- Claims registry, anomaly registry, provenance layer — untouched.
- Ledger schema except for the new `dsl_spec` column.

---

## 9. Acceptance criteria for R3-2 (duplicated from brief §3.9 for convenience)

- DSL-routed worker path is the default for the controller.
- Legacy path deprecated but importable with `DeprecationWarning`.
- All R3-1 pseudo-code implemented.
- 12+ new tests, all green, targeting the 8 scenarios in brief §3.8.
- Full suite green (core + kryptosbot).
- No regressions in self-test (K1/15, K2/17, K3/9345 on `--cycles 20000`).
- Dry-run execution of a controller cycle against a synthetic theory (DSL spec pre-populated) produces a valid `WorkerContract` without any Claude API call in the worker path.

---

## 10. Open questions for R3-3 (not blocking R3-2)

1. **R2-4 null-manifest family labels.** The `null_baselines/manifest.json` uses family strings — what exactly are the keys for the 4 matched-family nulls? Verify in R3-3 that `_matched_null_family` keys align with the manifest's actual entries. Minor renaming may be needed.
2. **Procedural-theory theorist frustration.** The 80% spec-production target is new — if the theorist persistently proposes procedural/polybius/quagmire theories that FB-1 rejects, the rate drops. R3-3's stop condition handles this, but expect prompt iteration.
3. **Information-gain estimate.** `HypothesisSpec.information_gain_bits_estimate` is theorist-populated and dispatcher-logged but not used for control flow. Consider whether R3-2's test pack should assert the field round-trips.

These are R3-3 / later-round questions, not R3-2 blockers.

---

*End of DSL_CUTOVER_CONTRACT.md. Companion document: CURRENT_WORKER_PATH.md — the pre-R3 map. Phase R3-2 implements strictly against this contract.*
