# KryptosBot Controller Architecture

## Overview

The KryptosBot research controller is a **persistent, theory-ledger-driven** system
that manages the K4 search process. Instead of running one-shot campaigns with
free-text session memory, it maintains structured state across cycles.

## Fail-Closed Contract Policy

**All controller boundaries enforce strict structured contracts.
Free text never drives control flow.**

| Boundary | Contract | Invalid payload behavior |
|----------|----------|------------------------|
| Worker → Controller | `WorkerContract` JSON in fenced block | `WorkerStatus.ERROR` with validation errors recorded |
| Theorist → Controller | JSON array of theory objects | Invalid items rejected and recorded in `TheoryParseReport.invalid` |
| MCP tool input | Enum/type validated args | Explicit error response to caller |
| Controller → Ledger | Typed `TheoryRecord` / `ExperimentRecord` | Type errors surface as exceptions |

**What this means operationally:**
- Workers that produce only prose get `ERROR` status. No status, score, or verdict
  is ever inferred from narrative text.
- Theorist proposals missing `core_claim`, `mechanism`, or `family` are rejected,
  not repaired. The controller falls back to programmatic generation.
- `narrative_summary` in worker output is stored for human review but is never
  parsed by the controller for any decision.
- Raw output is always preserved in `ParseResult.raw` or `raw_artifacts` for
  audit and debugging.

## Components

```
┌─────────────────────────────────────────────────────────┐
│                  ResearchController                      │
│  (controller.py — orchestrates the cycle)               │
│                                                          │
│  assess → generate → critic → dispatch → absorb → save  │
└──────────┬──────────┬──────────┬──────────┬─────────────┘
           │          │          │          │
     ┌─────▼─────┐   │    ┌─────▼─────┐   │
     │ Registries │   │    │  Critic   │   │
     │ (bootstrap)│   │    │ (gate)    │   │
     └───────────┘   │    └───────────┘   │
                     │                     │
           ┌─────────▼─────────┐  ┌───────▼────────┐
           │  Theory Ledger    │  │  Agent SDK      │
           │  (SQLite truth)   │  │  Workers        │
           └──────────────────┘  └──────┬─────────┘
                                         │
                                  ┌──────▼─────────┐
                                  │ Contracts       │
                                  │ (validation)    │
                                  └──────┬─────────┘
                                         │
                                  ┌──────▼─────────┐
                                  │ Research Tools  │
                                  │ + K4 Tools      │
                                  │ (MCP surface)   │
                                  └────────────────┘
```

## File Map

| File | Purpose |
|------|---------|
| `models.py` | All typed dataclasses + `ContractValidationError` |
| `contracts.py` | `ParseResult`, `validate_worker_contract()`, `validate_theory_proposals()` — centralized boundary validation |
| `theory_ledger.py` | SQLite-backed persistent ledger (6 tables) |
| `registries.py` | Bootstrap known families/anomalies/exhaustion data |
| `critic.py` | Pre-compute hypothesis rejection (deterministic, no API calls) |
| `research_tools.py` | MCP tools for structured research state access |
| `controller.py` | Persistent research controller orchestrating the full cycle |
| `run_controller.py` | CLI entrypoint |
| `provenance.py` | Provenance enums + `ScopeConditions` + `ProvenanceClaim` dataclass |
| `claims_registry.py` | `CANONICAL_CLAIMS`: single source of truth for epistemic status of every non-trivial claim |
| `claim_rendering.py` | Auto-hedging renderers (`render_claim`, `render_claim_inline`, `render_inventory`) |
| `claim_policy.py` | Policy gates (`can_use_as_hard_constraint`, `can_use_as_elimination_basis`, `can_promote_to_must_explain`, ...) |
| `EPISTEMIC_PROVENANCE.md` | Operational doctrine for the provenance layer |
| `hypothesis_dsl.py` | **Phase 4**: structured DSL for bounded cryptanalytic hypotheses. `HypothesisSpec`, `CipherLayer`, `ParamRange`, `NullBaselineSpec` dataclasses with fail-closed JSON validation |
| `job_dispatcher.py` | **Phase 4**: translates HypothesisSpec → kernel transforms → multiprocessing dispatch → kernel-verified `JobResult`. Admissibility pre-flight checks budget + translation coverage + exhaustion overlap |
| `dsl_tools.py` | **Phase 5**: 8 MCP tools exposing the DSL pipeline to agents (`submit_hypothesis_spec`, `poll_job`, `query_exhaustion`, `compute_null_baseline`, `score_candidate_canonical`, `get_procedural_recipe`, `enumerate_admissible_transforms`, `request_compute_budget_estimate`) |
| `null_baselines.py` | **Phase 6**: calibrated Monte Carlo null distributions with hybrid empirical + parametric tails (exact Binomial for crib_score, normal-approx for ngram_score). Powers the p-value gate in `alerts.py` |
| `procedural_enumerator.py` | **Phase 8**: parses `docs/procedural_recipes.json`, converts recipes into HypothesisSpecs, dispatches admissible ones as a batch (`--mode procedural_sweep` equivalent) |
| `self_test.py` | **Phase 7**: falsification test — K1/K2/K3 rediscovery benchmark. Dry-run mode directly enumerates Quagmire III candidates against kernel transforms |
| `alerts.py` | Contradiction-detector with Phase-3 ngram-floor + **Phase-6 p-value gate** (`p_value <= 1e-6`) |
| `contracts.py` | **Phase 3**: kernel-overrule verifier. Every worker output re-scored through `kryptos.kernel.scoring.aggregate.score_candidate`; adversarial 35-test battery at 100% line coverage |
| `ORIENT.md` | **Phase 9**: one-page operator onboarding — mission, three commands, where truth lives, failure modes |

## Provenance / Epistemic-Status Layer

The controller routes every "what we believe" statement through a structural
provenance layer so that epistemic hedges are **automatic** rather than
author-remembered. See `EPISTEMIC_PROVENANCE.md` for the full doctrine.

Key invariants enforced at the code level:

- Bean-reported statistics (`BEAN_REPORTED_NOT_RERUN`) and project-reverified
  statistical anomalies (`PROJECT_REVERIFIED_STATISTICAL_ANOMALY`) are blocked
  from hard-constraint / elimination-basis / must-explain use via `claim_policy`.
- Physical anomalies are split into separate `PHYSICAL_FACT` (existence) and
  `INTERPRETIVE_PHYSICAL_OBSERVATION` (cryptographic interpretation) claims.
  Physical existence is never auto-promoted to a cryptographic constraint.
- H1-conditional derivations (Bean equality, 242 inequalities, 101 linear
  constraints, 624 keystream vectors) carry scope conditions asserting direct
  positional crib mapping and crib-position-only scope. Hard-constraint use
  requires an explicit H1 workflow context.
- The retired null-palette `{B,G,I,K,O,W,Z}` construct is a `RETIRED_CLAIM`
  with policy gates blocking every downstream use except SUMMARY.
- The controller's theorist prompt injects anomaly-backed claims via
  `render_claim_inline`, which auto-prepends "Under H1 (...)" to
  H1-conditional claims and auto-appends the "Bean-reported, not
  independently re-derived" marker to external-author-reported claims.
- `run_controller.py --inventory` emits the auto-hedged, class-grouped
  provenance inventory — the canonical machine-generated replacement for
  hand-maintained "what we believe" documents.

## Preserved Components

| File | Role |
|------|------|
| `_archive/k4_tools_legacy.py` | Legacy MCP tools (`hill_climb`, `try_keyword_sweep`, `swap_and_test`). Quarantined 2026-04-26. The tools were `@tool`-registered and emitted `DeprecationWarning` on direct invocation, but `create_k4_mcp_server()` was never called in production — workers reach the live tools via `dsl_tools.create_dsl_mcp_server` and `research_tools.create_research_mcp_server` only |
| `sdk_wrapper.py` | Agent SDK error handling and cleanup |
| `oracle.py` | Local compute dispatcher (no API calls) |
| `_archive/database.py` | Legacy ResultsDB. Quarantined 2026-04-26 — was imported but never instantiated; production persistence is `theory_ledger.py` only |
| `config.py` | Runtime configuration and hypothesis status |
| `constants.py` | Bridge to kernel constants. **Phase 2**: retired palette symbols (`NULL_PALETTE`, `CONSENSUS_NULL_POSITIONS`, `BEAUFORT_KEYSTREAM_AT_CRIBS`) moved to `kryptos.kernel.retired` |
| `agent_runner.py` | Session launcher and output extraction |
| `_archive/` | **Phase 1**: quarantined legacy code (`campaign_v2.py`, `worker.py`). Imports broken; stubs at original paths raise `ImportError` with pointers |


## DSL + Dispatcher + Null Baselines (Phases 4-6)

The core architectural shift of the 2026 maturation: worker agents no longer
write cryptanalytic code in scratch directories. They specify **bounded
hypotheses** in a structured DSL (`hypothesis_dsl.py`); the dispatcher
(`job_dispatcher.py`) translates those specs into multiprocessing jobs
against `src/kryptos/kernel`, kernel-verifies every candidate, and returns
structured `JobResult` payloads.

```
Theorist → HypothesisSpec (JSON)
                │
                ▼
      validate_hypothesis_spec()  [fail-closed]
                │
                ▼
      check_admissibility()
                │ ├── translation coverage  (_SUPPORTED_KINDS)
                │ ├── compute budget        (cardinality × minute cap)
                │ └── exhaustion overlap    (exhaustion_log.json)
                ▼
      execute()
                │ ├── enumerate cartesian params across layers
                │ ├── multiprocessing.Pool(cpu_count()-2)
                │ ├── score_candidate() ← kernel overrule
                │ └── aggregate → JobResult {spec_hash, universe_hash, ...}
                ▼
      job_result_to_worker_contract()
                │
                ▼
      _verify_against_kernel()  [Phase 3 re-check]
                │
                ▼
      WorkerContract ready for ledger ingestion
```

### DSL coverage (Phase 4 + 8 + R2-2 + R3-0.5 + B-DSL-expanded)

The dispatcher's `_SUPPORTED_KINDS` set has grown over six separate
expansions. As of 2026-05-03 all DSL-valid kinds have dispatcher
translations (including `key_tape`, landed 2026-05-03). To get the live count programmatically:

```bash
PYTHONPATH=src python3 -c "
from kryptosbot.job_dispatcher import _SUPPORTED_KINDS
from kryptosbot.hypothesis_dsl import _VALID_CIPHER_KINDS
print('GAPS:', sorted(_VALID_CIPHER_KINDS - _SUPPORTED_KINDS))"
```

| Cipher kind | Dispatcher support | Notes |
|---|---|---|
| `identity`, `vigenere`, `beaufort`, `variant_beaufort`, `columnar`, `atbash` | ✅ AZ alphabet | Phase 4 |
| `rail_fence`, `route`, `myszkowski`, `quagmire` | ✅ via existing kernel transforms | B-DSL-expanded (2026-04-22) |
| `polybius` (variant=`bifid`) | ✅ via TransformType.BIFID | R3-0.5-3 (2026-04-21) |
| `grille` (Cardano permutation-only) | ✅ via TransformType.GRILLE | R3-0.5-2 (2026-04-21) |
| `procedural` with `recipe_id` | ✅ via procedural_enumerator.py | Phase 8 |
| KA alphabet for Vigenère-family | ✅ R2-2 (2026-04-21) — Phase 4 was AZ-only | Quagmire III enforces K1/K2 convention |
| `key_tape` | ✅ via `apply_key_tape()` kernel transform | Finite-tape additive cipher with optional null insertion (M1-M5 keystream-forensics class). Params: `tape` (tuple[int,...]), `variant` (vigenere/beaufort/var_beaufort), `direction`, `null_positions`, `null_rule` (skip/consume), `alphabet` (AZ/KA). Landed 2026-05-03. |

### Null-baseline calibration (Phase 6)

`null_baselines.py` holds the Monte Carlo null distributions used to
gate alerts on `p_value <= 1e-6`. Manifest committed at
`null_baselines/manifest.json`; full cache (multi-MB) gitignored under
`results/null_baselines/`.

| Scorer × Method | Tail computation |
|---|---|
| `crib_score × random_text` | **Exact Binomial(24, 1/26)** — closed-form, reliable below the 1/N empirical floor |
| `ngram_score × *` | Normal-approximation (CLT on ~94 quadgram log-probs) |
| `composite × *` | Empirical tail with 1/N upper bound |

On a cache miss, alerts fail open to legacy crib-score-only gating with
a visible `WARNING` — the framework never goes silent on a high score.

### Procedural recipe enumerator (Phase 8)

`procedural_enumerator.py` reads `docs/procedural_recipes.json` (~17
entries as of 2026-04-21: 12 DSL-translatable, 5 physical-only) and
converts admissible recipes into `HypothesisSpec` specs. Admissibility
filters:

- Physical-only recipes never dispatch (have no DSL template).
- Closed-anomaly recipes filtered when `open_anomaly_ids` is set.
- `known_eliminations` substring-match against the current
  assumption bundle.
- Total cardinality capped at `max_cost_minutes × 200_000`.

CLI:

```bash
PYTHONPATH=src python3 -m kryptosbot.procedural_enumerator --dry-run
PYTHONPATH=src python3 -m kryptosbot.procedural_enumerator --sweep --report-path RESULT.json
```

## Controller Cycle

Each cycle follows this sequence:

1. **Assess landscape** — Query ledger for status counts, active families,
   underexplored areas, open anomalies, and recent outcomes.

2. **Generate theories** — Ask an Agent SDK "theorist" session to propose
   structured hypotheses. Output is validated through `validate_theory_proposals()`.
   Invalid items are rejected and recorded. If no valid theories emerge,
   falls back to deterministic programmatic generation.

3. **Critic pass** — Each theory is evaluated deterministically:
   - Completeness check (required fields present?)
   - Family elimination (Tier 1/2 impossible?)
   - Duplicate detection (Jaccard similarity on mechanism + claim)
   - Contradiction check (violates known K4 constraints?)
   - Discriminability (has kill criteria?)
   - Information gain estimation

4. **Dispatch** — Approved theories are sent to Agent SDK workers. Workers
   are instructed to emit a fenced JSON block conforming to `WorkerContract`.

5. **Absorb** — Worker output is parsed through `validate_worker_contract()`.
   Valid results update theory status. Invalid results produce `WorkerStatus.ERROR`
   with the validation errors recorded in the experiment. **No status, score,
   or verdict is inferred from narrative text.**

6. **Persist** — Controller state saved to ledger for resume.

## Contract Validation (contracts.py)

The `contracts.py` module is the single chokepoint for all boundary parsing.

### ParseResult

```python
@dataclass
class ParseResult(Generic[T]):
    is_valid: bool      # True = value is populated; False = errors explain why
    value: Optional[T]  # The validated payload (only when is_valid)
    errors: list[str]   # Explicit validation errors (only when not is_valid)
    raw: str            # Original text, always preserved for audit
```

### Worker Contract Validation

`validate_worker_contract(raw, hypothesis_id) → ParseResult[WorkerContract]`

1. Extracts the last fenced `json` block (```` ```json ... ``` ````)
2. Parses as JSON dict
3. Validates: `status` required, enum value valid, numeric/boolean/list types correct
4. Constructs `WorkerContract` with strict field checking

**If any step fails**: `ParseResult.fail(errors=[...], raw=raw)`.
The controller creates a `WorkerStatus.ERROR` contract. No heuristic fallback.

**Bare JSON in prose is NOT extracted** — this prevents false positives from
example JSON in narrative discussions.

### Theory Proposal Validation

`validate_theory_proposals(raw) → TheoryParseReport`

1. Finds the outermost JSON array in the text
2. Validates each item: required fields (`core_claim`, `mechanism`, `family`)
   present and non-empty, list fields are lists, dict fields are dicts
3. Valid items become `TheoryRecord`; invalid items are recorded with their
   index and error reason

## Worker Contract

Workers must emit a fenced JSON block:

````
```json
{
  "status": "success|disproved|inconclusive|error",
  "score": 0.0,
  "crib_score": 0,
  "bean_passed": false,
  "best_plaintext": "",
  "disproof_evidence": [],
  "supporting_evidence": [],
  "next_action": "",
  "family_generalization": "",
  "narrative_summary": "..."
}
```
````

**Required field**: `status` (valid enum value).
**Validated fields**: `score` (numeric), `crib_score` (numeric), `bean_passed` (boolean),
`disproof_evidence` (list), `supporting_evidence` (list).

`hypothesis_id` is always overridden by the controller to match the dispatched theory,
regardless of what the worker writes. This prevents workers from accidentally or
intentionally updating the wrong theory.

## Theory Ledger Schema

The ledger stores:
- **theories**: Full hypothesis records with lifecycle tracking
- **experiments**: Execution records linked to theories
- **anomalies**: Tracked unexplained observations
- **families**: Cipher family status and elimination tiers
- **evidence**: Links between theories and supporting/disproving evidence
- **controller_state**: Singleton row with controller cycle state

## Usage

```bash
# Full run (default: 10 cycles, 5 theories each)
python3 kryptosbot/run_controller.py

# Dry run (generate + critic only, no dispatch)
python3 kryptosbot/run_controller.py --dry-run --theories 10

# Check status
python3 kryptosbot/run_controller.py --status

# Conservative run
python3 kryptosbot/run_controller.py --cycles 2 --theories 3

# Ledger summary
python3 kryptosbot/run_controller.py --summary
```

## Debugging Invalid Payloads

When a worker fails to produce valid structured output:

1. **Experiment record**: The experiment is recorded with a `WorkerContract`
   whose `status=error` and `error` field contains the validation message(s).
2. **Raw output**: Stored in `raw_artifacts.raw_output_preview` (first 5000 chars)
   on the error contract.
3. **Theory status**: Set to `COMPLETED` (not `ELIMINATED` — we don't know
   what happened, so we don't claim the theory was disproved).
4. **Logs**: `kryptosbot.controller` logs the validation errors at WARNING level.

To find all parse failures:
```sql
SELECT hypothesis_id, result
FROM experiments
WHERE json_extract(result, '$.status') = 'error'
  AND json_extract(result, '$.error') LIKE '%Contract validation%';
```

## Startup Reconciliation

On every startup (both `controller.run()` and `do_run()`), the controller
calls `TheoryLedger.reconcile_orphaned_running()`. This transitions any
theories stuck in `RUNNING` status to `COMPLETED` with a failure reason
of `"Orphaned: found in RUNNING at startup after process restart"`.

**Rationale:** If the process crashes or is killed while workers are active,
those theories remain in RUNNING forever. No worker is alive to produce a
result, so the controller would never generate new work for that slot.
Reconciliation ensures the ledger reflects reality.

The reconciliation is idempotent: calling it when no theories are RUNNING
is a no-op.

## Session-Local Telemetry

The cycle delta shown in the landscape (`new_tested`, `new_eliminated`) is
computed relative to a **session baseline** snapshot taken at the start of
`run()`. This means:

- First cycle always shows delta = 0 (nothing new *this session*)
- Subsequent cycles show only work done in the current run
- Restarting the controller resets the baseline

Previously, the delta used ephemeral attributes (`_prev_tested_count`)
that defaulted to 0 on fresh start, causing the first cycle to show the
entire historical count as "new" work.

## Removed: budget_limit_usd and local_only

- `budget_limit_usd` was stored in `ControllerConfig` and `ControllerState`
  but never checked or enforced. Removed to avoid implying cost control exists.
- `local_only` was displayed in the startup banner but never routed differently;
  the controller always dispatches via Agent SDK. Removed to avoid implying
  an oracle-only mode exists. Use `--dry-run` to skip dispatch entirely.

## Migration from campaign_v2

The controller replaces campaign_v2 as the primary entrypoint.

| Aspect | campaign_v2 | controller |
|--------|------------|------------|
| State | Free-text journal + ResultsDB | Structured theory ledger |
| Hypothesis generation | Prompt-driven, one-shot | Structured, ledger-aware, critic-gated |
| Worker output | Prose parsing (regex heuristics) | **Strict fenced-JSON contract, fail-closed** |
| Invalid output | Heuristic inference from keywords | Explicit ERROR, raw preserved for audit |
| Family tracking | Manual prompt injection | Structured family registry |
| Deduplication | None (repeats common) | Content-addressed hypothesis_id |
| Resume | Session-based | Cycle-based, persistent state |
| Research tools | K4 compute only | K4 compute + research state access |

campaign_v2.py is preserved for backward compatibility but is no longer
the recommended entrypoint.

## Family-Yield Feedback Loop (Phase 1, 2026-05-16)

A memory-to-prompt feedback loop driven by ledger yield statistics.

**Authority model:**

| authority           | surface                                    |
| ------------------- | ------------------------------------------ |
| ledger              | source of record (theories.* columns)      |
| family_yield.py     | source of derived policy truth             |
| theorist prompt     | advisory rendering for proposal shaping    |
| critic              | enforcement (REJECT_EMPIRICALLY_DEAD)      |

`_assess_landscape` snapshots `family_yield_stats()`, `subfamily_index()`,
and `mechanism_signature_index()` once per cycle. Both the theorist
prompt (advisory) and the critic gate (enforcement) read the same
snapshot; divergence is structurally impossible.

Bypass criteria for an empirically-dead family: the theory must
specify a subfamily NOT in `prior_subfamilies_in_family` AND a
`mechanism_signature` (canonical DSL hash for Category-A, structured
hash of family+subfamily+mechanism_tokens+anomalies+anchors+method
for Category-B) NOT in `prior_mechanism_signatures_in_family`.
`novelty_basis` prose explains the bypass but does not define it.

Escape telemetry is written by the single chokepoint
`_write_cycle_escape_summary`, called from every cycle-exit path
(no-candidates, all-rejected, success). State persisted on
`ControllerState.escape_needed_streak` and four sibling fields.

See `docs/specs/2026-05-16-yield-feedback-design.md` for full spec.
