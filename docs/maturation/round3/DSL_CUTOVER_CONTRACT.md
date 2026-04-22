# DSL Cutover Contract — R3-2 Implementation Target

**Phase:** R3-1 design, revised 2026-04-21 for R3-1 §3.5 Option γ escalation
**Consumer:** Phase R3-2 implementation (after R3-0.5 DSL completion lands)
**Purpose:** Specify exactly what R3-2 implements, in enough detail that R3-2 needs no further design decisions.
**Revision note:** the original contract specified a single FB-1 fallback
policy. R3-1's audit surfaced that FB-1 uniformly would reject ~95% of
theorist output because many families are non-cipher-computational.
Operator directed (2026-04-21) adoption of a hybrid fallback: FB-1 for
cipher-family gaps and malformations, FB-2-tagged-as-non_dsl_category
for methodological/investigative families. See §2.

---

## 1. Theorist output contract

### 1.1 New required field: `dsl_spec`

The theorist prompt currently lists `"dsl_spec": null` as an **optional** JSON field (see `kryptosbot/controller.py:1557`, and the explanatory block at 1561–1567: "Phase 4 accepts null here; leave null when no clean DSL translation exists"). R3-2 makes it **required**.

Every theory proposal must include a `dsl_spec` field that is either:

- A JSON object conforming to `kryptosbot.hypothesis_dsl.HypothesisSpec.to_dict()` — a computable specification; OR
- The literal `null` — an explicit statement that no DSL translation exists.

Ambiguous values (missing field, empty object `{}`, empty string) cause the theory to land in `TheoryParseReport.invalid` with reason `"dsl_spec must be a HypothesisSpec object or null"`.

### 1.2 Supported cipher kinds

**This section is auto-authoritative.** The critic's translatability
check reads `kryptosbot.job_dispatcher._SUPPORTED_KINDS` at runtime —
so whenever that frozenset grows, the critic's pass-through widens
automatically.

**Pre-R3-0.5 state (R3-1 exit, 2026-04-21):**

```
identity, vigenere, beaufort, variant_beaufort, columnar, atbash
```

**Current state (R3-0.5 exit, 2026-04-21 — 9 entries):**

```
identity, vigenere, beaufort, variant_beaufort, columnar, atbash,
procedural, grille, polybius
```

R3-0.5 added the three rightmost kinds. `procedural` dispatches via
spec-level expansion through `procedural_enumerator.recipe_to_spec`;
`grille` dispatches via `TransformType.GRILLE` delegating to
`apply_grille_permutation` under the permutation-only interpretation;
`polybius` dispatches via the existing `TransformType.BIFID` (straight
polybius is deferred).

**Kinds in the DSL type literal but still not translatable:**

```
rail_fence, route, myszkowski, quagmire, key_tape
```

(`key_tape` is intentionally deferred to a later brief per operator
direction — the OTP-like finite-tape model has enough structural
peculiarity to merit its own design cycle.)

Theories whose pipeline includes any of the still-untranslatable
kinds and whose family is NOT in `NON_DSL_FAMILIES` (§2.2) will be
rejected by the critic with reason
`"dsl_untranslatable: kind <X> has no dispatcher translation in R3"`.

This split is a deliberate consequence of brief §6.1 ("Do not expand
the DSL") and §policy. Growing `_SUPPORTED_KINDS` is done in separate
briefs (R3-0.5 being the first). R3-2 wires **whatever**
`_SUPPORTED_KINDS` contains at the time R3-2 runs; no source change
needed in this contract when new kinds are added.

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

Theorist's natural-language hypothesis: *"K4 uses a rail-fence transposition (3 rails) applied to the carved text."*

```json
{
  "hypothesis_id": "<filled by controller from core_claim>",
  "dsl_spec": null,
  "core_claim": "...",
  "mechanism": "Rail-fence depth-3 transposition",
  "notes": "rail_fence, route, myszkowski, quagmire, and key_tape still lack dispatcher translations after R3-0.5. This theory correctly declares dsl_spec=null rather than fabricating a spec the framework cannot execute."
}
```

**Outcome:** critic rejects with `CriticDecision.REJECT_UNDERCONSTRAINED`, reason `"dsl_untranslatable: cipher-family theory declared dsl_spec=null; DSL requires a spec for Category-A dispatch"` (per §6.5 hybrid-aware critic sketch).

Revised 2026-04-21 after R3-0.5 landed: the original Example C used a procedural P-F1-1 hypothesis, but R3-0.5-1 added the procedural translator, making that particular theory dispatchable. The example now uses `rail_fence`, which remains untranslatable.

This is the correct behaviour per brief §6.1. R3-3's real-theorist test measures Category-A spec-production rate (§2.7) only; Category-B methodological theories are not expected to carry DSL specs and are not counted against the 80% floor.

### 1.4 Validation order

`validate_theory_proposals` at `kryptosbot/contracts.py:417` runs these checks in order (new step bolded):

1. Extract JSON array from raw theorist output.
2. Each item has the required string fields (`title`, `core_claim`, `mechanism`, `family`).
3. List fields are lists.
4. `anomalies_exploited` entries are canonical anomaly_ids.
5. `minimal_test_spec` is a dict (optional).
6. **NEW: `dsl_spec` is either a dict or literal `null`. Boundary parsing does NOT structurally validate the spec object beyond that type check.** This is the landed behavior in `kryptosbot/contracts.py`: shape-level validation is deferred to the critic's Category-A/C check so malformed specs are rejected as `dsl_untranslatable` rather than silently dropped at boundary time.
7. Construct `TheoryRecord` with the new `dsl_spec` attribute populated (`dict` for success, `{}` for null / absent). Structural validation then runs in `TheoryCritic.evaluate()`, which calls `validate_hypothesis_spec(...)`.

---

## 2. Fallback policy: hybrid (FB-1 for cipher gaps + malformations, FB-2-tagged for non-cipher families)

Revised 2026-04-21 per R3-1 §3.5 Option γ escalation. The single-policy
FB-1 originally proposed in the brief would have rejected an estimated
95%+ of historical theorist output because most theorist proposals
either (a) target cipher kinds that the DSL couldn't yet translate, or
(b) belong to methodological/investigative families that are not cipher
theories at all. The hybrid splits the handling of those two cases.

### 2.1 Three categories a theory can fall into

Given an incoming `TheoryRecord` with its `family` field and a
(possibly present, possibly null) `dsl_spec`, the critic classifies
into one of three categories:

**Category A — cipher theory, DSL-translatable.** The theory belongs
to a cipher family and carries a valid `HypothesisSpec` whose pipeline
uses only kinds in `_SUPPORTED_KINDS`. Pass through the critic's
remaining checks; dispatch via the new DSL `_run_worker`.

**Category B — non-cipher theory, routed to legacy path.** The
theory's `family` is in `NON_DSL_FAMILIES` (see §2.2). The critic does
not require a `dsl_spec` for these theories. They route through
`_run_worker_legacy` with `worker_role="agent_sdk_non_dsl_category"`,
preserving the pre-R3 dispatch behaviour for the methodological /
investigative work that does not correspond to a cipher computation.
This is the **FB-2 (tagged-as-non_dsl_category)** branch of the
hybrid.

**Category C — malformation or untranslatable cipher.** Neither A
nor B. The theory's family implies a cipher computation (not in
`NON_DSL_FAMILIES`), but the `dsl_spec` is null / malformed / uses a
kind outside `_SUPPORTED_KINDS`. The critic rejects with
`CriticDecision.REJECT_UNDERCONSTRAINED` and reason
`"dsl_untranslatable"`. This is the **FB-1** branch of the hybrid.

### 2.2 `NON_DSL_FAMILIES` definition

Lives in `kryptosbot/critic.py` (landed by R3-0.5-1, see the R3.5
brief at `docs/maturation/round3/CLAUDE_CODE_BRIEF_round3_0_5_dsl_completion.md`):

```python
NON_DSL_FAMILIES: frozenset[str] = frozenset({
    "geometry",
    "k2_coords",
    "geodetic",
    "antipodes",
    "archive_evidence",
    "crib_analysis",
    "k3_continuity",
})
```

Rationale per family:

| Family | Why non-cipher |
|---|---|
| `geometry` | Spatial / diagrammatic analysis of the sculpture and its inscriptions |
| `k2_coords` | Coordinate derivation from K2's disclosed latitude/longitude — investigative |
| `geodetic` | Geodetic computation (bearings, distances) — not a cipher op |
| `antipodes` | Analysis of the Antipodes sculpture — reference material work |
| `archive_evidence` | AAA archive documents — evidence gathering |
| `crib_analysis` | Methodological exploration of crib structure — meta-research |
| `k3_continuity` | Relation of K3's method to K4 — methodological |

Theorists who file proposals in these families are producing research
evidence (coordinates, annotations, relationships) rather than
decrypt candidates. Forcing them through the DSL would be a category
error: the DSL describes cipher computations, and these proposals
are not cipher computations.

Membership is deliberately narrow. The list is not open-ended — it
covers families the theorist prompt and existing theorist output have
used non-cipher-computationally. Additions require a separate brief.

### 2.3 Why not uniform FB-1?

1. **Forces a false choice on theorists.** A uniform FB-1 would require
   every theory to carry a cipher spec. Many legitimate theorist
   outputs (e.g., "K2's 38° coordinate lies on a line through the
   pool and the sculpture; this suggests a geodetic offset for K4")
   are not computations and have no valid DSL form.
2. **Breaks the procedural paradigm.** MEMORY.md's
   `procedural_paradigm_shift.md` + the theorist prompt at
   `controller.py:1474–1491` actively steer theorists to procedural
   output. A uniform FB-1 rejection would silently rotate the prompt
   behaviour out.
3. **Loses evidence.** Non-cipher theories often surface anomalies or
   archive findings that feed future cipher hypotheses. Rejecting
   them at the critic stops that feed.

### 2.4 Why not uniform FB-2?

1. **Defeats R3's purpose.** The postmortem §6.1.6 gap is precisely
   that cipher theories aren't routed through the DSL. Uniform FB-2
   keeps every theory on the legacy path — nothing changes.
2. **Admits malformations.** Uniform FB-2 would route a broken or
   empty `dsl_spec` through the worker, wasting a subscription turn on
   a theory the controller already knows is not actionable.
3. **Breaks mortality telemetry.** R3's whole reason for existing is
   to populate the dispatcher-reject column of the mortality table.
   Uniform FB-2 leaves that column empty.

### 2.5 Dispatch fan-out (controller implementation)

`_dispatch_theories` at `kryptosbot/controller.py:1638` fans out per
theory. Under R3-2, the fan-out uses the category classification:

```python
from .critic import NON_DSL_FAMILIES

tasks = []
for theory in theories:
    theory.status = TheoryStatus.RUNNING
    self.ledger.upsert_theory(theory)
    if theory.family in NON_DSL_FAMILIES:
        # Category B — non-cipher; legacy SDK path with explicit tag.
        tasks.append(
            self._run_worker_legacy(theory, on_worker_message,
                                    tag="non_dsl_category")
        )
    else:
        # Category A — cipher; DSL dispatch.
        tasks.append(self._run_worker(theory, on_worker_message))
```

Category C is not reached here because the critic rejects before
dispatch: Category-C theories never reach `_dispatch_theories`.

### 2.6 Worker-role tagging

Three distinct `WorkerContract.worker_role` values appear post-R3:

| `worker_role` | Dispatch path | Category |
|---|---|---|
| `"dsl_dispatcher"` | `_run_worker` → `job_dispatcher.execute` | A |
| `"agent_sdk_non_dsl_category"` | `_run_worker_legacy` (with tag) | B |
| `"agent_sdk"` | `_run_worker_legacy` (without tag) | (deprecated, R4 removes) |

The legacy "`agent_sdk`" role exists only because R4 removes
`_run_worker_legacy` entirely. During R3, all Category-B dispatches
produce `"agent_sdk_non_dsl_category"` — the untagged value is a
hangover that should not appear on any freshly-produced contract.

### 2.7 Implications for R3-3 spec-production rate

R3-3 §4.4 measures "fraction of real-theorist proposals that produce a
valid DSL spec." Under the hybrid policy, this is measured **only
over Category-A theories** — Category-B theories have no obligation
to emit a `dsl_spec`, and counting their absence would artificially
depress the metric.

Concretely:

```
spec_production_rate = (# Category-A theories with valid dsl_spec)
                     / (# Category-A theories)
```

This keeps the 80% target meaningful — it measures how well the
theorist produces DSL specs for the theories that are supposed to have
them, not how well it produces DSL specs for non-cipher work that
shouldn't have them.

R3-3's readiness test must split the metrics by category and report
both. A Category-A spec-production rate below 80% still triggers
the brief's stop condition.

### 2.8 Implications for mortality telemetry

The K4 run postmortem's stage table (see `K4_RUN_POSTMORTEM.md` §6.1.2)
now has finer resolution. Under R3 with the hybrid policy, the
stages breakdown by category:

| Stage | Category-A path | Category-B path |
|---|---|---|
| A. Theorist never proposed | identical | identical |
| B. Critic rejected | `reject_underconstrained: dsl_untranslatable` is new sub-reason | critic does NOT require dsl_spec; reject for other reasons only |
| C. Red-team killed | identical | identical |
| D. Dispatcher rejected | admissibility reject, new non-zero | not reached (no dispatcher on legacy path) |
| E. Scoring outcomes (dispatched) | kernel-verified via `JobResult` | worker-reported via `WorkerContract` (Phase-3 overrule still applies) |
| F. Error / infra | identical | identical |

R3-4's updated run protocol documents this split explicitly.

---

## 3. The new `_run_worker` — pseudo-code

**Scope reminder.** The pseudo-code below is the Category-A (DSL
cipher) dispatch path. Category B (`family ∈ NON_DSL_FAMILIES`)
theories never reach this function — they are fanned out to
`_run_worker_legacy` by `_dispatch_theories` (see §2.5). Category C
theories never reach dispatch at all — the critic rejects them before
`_dispatch_theories` runs.


```python
async def _run_worker(
    self, theory: TheoryRecord, on_message: Any = None,
) -> WorkerContract:
    """Dispatch one Category-A (cipher) theory via the DSL.

    No Claude call on this path. Under the hybrid fallback (see §2),
    Category-B theories (family ∈ NON_DSL_FAMILIES) route to
    _run_worker_legacy instead and never reach this function.
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

### 6.1 Legacy path retention (revised for hybrid policy)

Under the §2 hybrid policy, `_run_worker_legacy` is **not deprecated**
in R3 — it remains the live dispatch path for Category-B theories
(`family ∈ NON_DSL_FAMILIES`). A later brief (post-R3) decides
whether and how to retire the legacy path once Category-B throughput
is observed in production.

R3-2 refactors `_run_worker_legacy` to accept an optional `tag`
keyword argument:

```python
async def _run_worker_legacy(
    self,
    theory: TheoryRecord,
    on_message: Any = None,
    *,
    tag: Optional[str] = None,
) -> WorkerContract:
    """Pre-R3 SDK-subprocess worker path. Live in R3 for Category-B
    theories (see DSL_CUTOVER_CONTRACT §2). Dispatched via
    _dispatch_theories when theory.family ∈ NON_DSL_FAMILIES.

    Args:
        tag: Optional worker_role suffix. When "non_dsl_category",
             the returned WorkerContract carries
             worker_role="agent_sdk_non_dsl_category". When None
             (legacy test harnesses, one-off scripts), role defaults
             to "agent_sdk".
    """
    # ... existing pre-R3 body unchanged except that the final
    # contract.worker_role assignment respects `tag`:
    if tag == "non_dsl_category":
        contract.worker_role = "agent_sdk_non_dsl_category"
    else:
        contract.worker_role = "agent_sdk"
    ...
```

No `DeprecationWarning` is emitted. `_dispatch_theories` calls it
directly for Category-B theories (see §2.5).

### 6.2 Test compatibility

Tests that exercised the pre-R3 SDK-subprocess path continue to
work without wrapping, because the function is live. R3-2 adds
**new** tests covering the tagging behaviour:

```python
# R3-2 new test: legacy path emits correct tagged role
contract = await controller._run_worker_legacy(
    category_b_theory, tag="non_dsl_category",
)
assert contract.worker_role == "agent_sdk_non_dsl_category"
```

Pre-existing tests that expected `worker_role == "agent_sdk"` on
untagged calls pass unchanged (the default branch).

### 6.3 `_build_worker_prompt` preservation

`_build_worker_prompt` at line 2219 is called only by
`_run_worker_legacy`. It stays intact in the source. It is NOT
called by the new `_run_worker`. The prompt's "DSL-FIRST EXECUTION"
section (lines 2260–2284) remains live-prompt text because the
Category-B legacy worker can still benefit from DSL suggestions
(e.g., a coord-lie theory that wants to use the DSL's
`score_candidate_canonical` for candidate verification). The
section's framing as "PREFERRED PATH" is slightly aspirational under
R3 — Category-B workers are free to use DSL tools but aren't required
to — and a future minor prompt edit could clarify that. Not in R3-2
scope.

### 6.4 Theorist prompt edits

`_build_theorist_prompt`:

- Remove the phrase "`dsl_spec` is OPTIONAL" and the `"dsl_spec": null` default.
- Replace with: `"dsl_spec" must be either a HypothesisSpec object or explicit null; absent/empty specs are rejected.`
- Inject the three examples from §1.3 verbatim.
- Add the supported-kinds list from §1.2 with the warning that other kinds will be rejected.
- Keep the existing R2-3 override-exhaustion block (line 1460) unchanged. The override lives on `HypothesisSpec.override_exhaustion`/`override_justification` (already wired); theorists continue to populate it on their specs.

### 6.5 Critic prompt changes (hybrid-aware)

The deterministic critic (`kryptosbot/critic.py`) has no LLM prompt.
R3-2's addition is a new early code check in `TheoryCritic.evaluate`
that classifies the theory by category (§2.1) before running the
dsl_spec validation:

```python
# --- Check 0 (R3-2): category classification + DSL translatability ---
from .hypothesis_dsl import HypothesisSpec, validate_hypothesis_spec
from .job_dispatcher import _kind_has_translation, _SUPPORTED_KINDS
# NON_DSL_FAMILIES lives in this module (landed by R3-0.5-1).

if theory.family in NON_DSL_FAMILIES:
    # Category B — non-cipher / investigative. No dsl_spec required;
    # skip the translatability check and proceed to existing checks.
    # Dispatch routing happens later in _dispatch_theories (§2.5).
    pass
else:
    # Category A (pass) or C (reject). Translate the spec.
    if not theory.dsl_spec:
        return CriticVerdict(
            decision=CriticDecision.REJECT_UNDERCONSTRAINED,
            confidence=1.0,
            reasons=[
                "dsl_untranslatable: cipher-family theory declared "
                "dsl_spec=null; DSL requires a spec for Category-A "
                "dispatch (see DSL_CUTOVER_CONTRACT §2)",
            ],
        )
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
                f"dsl_untranslatable: kinds {untranslatable} have no "
                f"dispatcher translation in R3 "
                f"(supported: {sorted(_SUPPORTED_KINDS)})",
            ],
        )
# Fall through to existing checks (completeness, family-elimination, ...).
```

The existing R2-3 override-duplicate check at
`_check_override_duplicate` (line 508) stays. It is now
defense-in-depth: the dispatcher's admissibility check also enforces
override semantics at spec level.

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
- Day-4 persona routing for theorists, critics, red-team, stat-audit, lead-pursuit, synthesis — untouched. Category-A workers (DSL path) don't use personas because they don't run LLMs; Category-B workers (legacy path) continue to use Day-4 persona selection as before.
- Pantheon sibling call architecture — untouched.
- Claims registry, anomaly registry, provenance layer — untouched.
- Ledger schema except for the new `dsl_spec` column.

---

## 9. Acceptance criteria for R3-2

Combines brief §3.9 with the hybrid fallback additions from §2:

- DSL-routed worker path is the default for cipher theories
  (Category A).
- Legacy path retained (no `DeprecationWarning` — §2 revision kept
  it live for Category B). The deprecation planned in the original
  R3 brief is replaced with dual-path coexistence for the duration
  of R3; a later brief decides legacy-path retirement.
- `NON_DSL_FAMILIES` constant lands in `kryptosbot/critic.py`
  (landed by R3-0.5-1 — R3-2 just imports and uses it).
- `_dispatch_theories` fan-out per §2.5.
- Critic early Category-C check emits
  `CriticDecision.REJECT_UNDERCONSTRAINED` with
  `"dsl_untranslatable"` reason for cipher theories missing a
  translatable `dsl_spec`; skips the check for theories in
  `NON_DSL_FAMILIES`.
- `WorkerContract.worker_role` values per §2.6.
- All R3-1 pseudo-code implemented (for Category A).
- 12+ new tests, all green, targeting the 8 scenarios in brief §3.8
  plus at least 3 new scenarios covering the hybrid split:
  (a) Category-B theory with absent `dsl_spec` passes critic and
  dispatches via legacy path with tagged role;
  (b) Category-A theory with untranslatable kind is rejected at
  critic;
  (c) Mortality telemetry reports the two Category-A/B paths
  distinctly.
- Full suite green (core + kryptosbot).
- No regressions in self-test (K1/15, K2/17, K3/9345 on
  `--cycles 20000`).
- Dry-run execution of a controller cycle against a synthetic
  Category-A theory (DSL spec pre-populated) produces a valid
  `WorkerContract` without any Claude API call in the worker path.
- Dry-run execution of a synthetic Category-B theory produces a
  `WorkerContract` with `worker_role="agent_sdk_non_dsl_category"`
  (mock the SDK subprocess in the test).

---

## 10. Open questions for R3-3 (not blocking R3-2)

1. **R2-4 null-manifest family labels.** The `null_baselines/manifest.json` uses family strings — what exactly are the keys for the 4 matched-family nulls? Verify in R3-3 that `_matched_null_family` keys align with the manifest's actual entries. Minor renaming may be needed.
2. **Procedural/grille/polybius theorist behaviour.** R3-0.5 adds translators for these three kinds. R3-3's real-theorist test must measure the spec-production rate over Category-A theories only (§2.7). Expect one prompt iteration to teach the theorist about the three new kinds — the prompt hasn't had them before.
3. **key_tape and the remaining untranslated kinds.** `rail_fence`, `route`, `myszkowski`, `quagmire`, and `key_tape` remain FB-1-rejected after R3-0.5. If theorists persist in proposing them (especially `key_tape`, which is a live research angle per MEMORY.md `project_keystream_forensics_*`), R3-3's prompt iteration should add them to the "explicitly deferred" list in the theorist prompt so the theorist stops pointing at them.
4. **Category-B theorist behaviour.** The hybrid policy keeps Category-B theories alive; R3-3 should monitor the ratio Category-A:Category-B in real cycles. A healthy research loop probably wants the ratio to favour Category-A 3:1 or more. If Category-B dominates, the controller has drifted into methodological work at the expense of cipher testing.
5. **Information-gain estimate.** `HypothesisSpec.information_gain_bits_estimate` is theorist-populated and dispatcher-logged but not used for control flow. Consider whether R3-2's test pack should assert the field round-trips.

These are R3-3 / later-round questions, not R3-2 blockers.

---

*End of DSL_CUTOVER_CONTRACT.md. Companion document: CURRENT_WORKER_PATH.md — the pre-R3 map. Phase R3-2 implements strictly against this contract.*
