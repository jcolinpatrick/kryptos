# Phase 4 — Hypothesis DSL + job dispatcher — Report

**Date:** 2026-04-21
**Entry baseline:** `941371a maturation phase 03: kernel-overrule adversarial test battery`
**Goal (brief §6):** shift from *LLM writes cryptanalysis code in a scratch
directory* to *LLM specifies bounded hypotheses in a structured DSL; the
controller translates into multiprocessing jobs against* `src/kryptos/`.

The 28-core VM currently sits idle during worker execution because the
worker-scratch path is single-threaded LLM-driven Python. The DSL + dispatcher
change the LLM's job from *compute executor* to *hypothesis specifier* and
routes the actual compute through kernel infrastructure that has been
battle-tested and parallel-safe for months.

---

## 1. What shipped

| Module | Purpose | Lines |
|---|---|---|
| `kryptosbot/hypothesis_dsl.py` | Structured DSL (dataclasses + JSON + validator) | 398 |
| `kryptosbot/job_dispatcher.py` | Admissibility + translation + dispatch + verify + JobResult | 557 |
| `kryptosbot/tests/test_hypothesis_dsl.py` | DSL test battery | 42 tests |
| `kryptosbot/tests/test_job_dispatcher.py` | Dispatcher test battery | 36 tests |

**Test delta this phase:** `kryptosbot/tests/` 399 → 477 (+78 tests).
Brief's §6.5 minimum was ≥15 new tests. All 78 run in 0.20s.

Minimal controller wiring:

- `kryptosbot/controller.py::_build_theorist_prompt` now includes one
  optional `dsl_spec` field in the output-format example with a pointer
  to the DSL. Kept **OPTIONAL** for Phase 4 so the existing theorist flow
  is not disturbed (brief §6.6 backward-compat).
- `kryptosbot.job_dispatcher.job_result_to_worker_contract` converts a
  `JobResult` to a `WorkerContract` suitable for ledger ingestion. The
  Phase-3 `_verify_against_kernel` runs on the produced contract, so the
  kernel-overrule guarantee still holds on this path. Default controller
  flow does **not** call this helper — future sessions wire it in.

---

## 2. DSL schema

### 2.1 Top-level: `HypothesisSpec`

```jsonc
{
  "hypothesis_id": "T-EXAMPLE-001",              // inherits from TheoryRecord
  "pipeline": [ /* CipherLayer[] */ ],           // applied outer-first during decrypt
  "crib_alignment": "direct_positional",         // "direct_positional" | "post_transposition" | "free"
  "scoring": "composite",                        // "crib_only" | "crib_plus_bean" | "ngram_vs_null" | "composite"
  "null_baseline": null,                         // NullBaselineSpec | null (Phase 6 populates)
  "information_gain_bits_estimate": 0.0,         // theorist's a-priori guess
  "success_criteria": { /* dict */ },            // what counts as a hit
  "kill_criteria": { /* dict */ },               // what counts as a definitive elimination
  "compute_budget_cpu_minutes": 30,              // hard ceiling; dispatcher enforces
  "checkpoint_every_sec": 60,
  "assumption_bundle": ["H1_direct_positional"], // used for exhaustion-log matching
  "notes": ""                                    // free-form; never parsed
}
```

Every field has runtime validation. `HypothesisSpec.spec_hash` is the
sha256-16 deduplication key over the canonical serialization; two
field-order-equivalent specs have the same hash.

### 2.2 Layer: `CipherLayer`

```jsonc
{
  "kind": "vigenere",                            // see _VALID_CIPHER_KINDS
  "alphabet": "AZ",                              // "AZ" | "KA" | "keyword_mixed"
  "params": [ /* ParamRange[] */ ],
  "recipe_id": null                              // required for kind=="procedural"
}
```

### 2.3 Range: `ParamRange`

Exactly one of two modes:

- **Explicit enumeration**: `{"name": "keyword", "values": ["PALIMPSEST", "ABSCISSA"]}`
- **Integer range**: `{"name": "width", "start": 5, "stop": 15}` → `[5, 6, ..., 14]`

Built-in `cardinality_cap` (default 10_000) rejects runaway ranges at
validate time. The dispatcher further checks
`expected_cardinality() × per-minute-cap` against
`compute_budget_cpu_minutes` at admissibility time.

### 2.4 Valid `CipherKind` registry

| Kind | DSL-valid | Dispatcher-supported (Phase 4) |
|---|---|---|
| `identity` | ✅ | ✅ |
| `vigenere` | ✅ | ✅ (AZ only; KA is Phase 5) |
| `beaufort` | ✅ | ✅ (AZ only) |
| `variant_beaufort` | ✅ | ✅ (AZ only) |
| `columnar` | ✅ | ✅ (requires explicit `col_order`) |
| `atbash` | ✅ | ✅ |
| `rail_fence` | ✅ | ⏳ Phase 5 |
| `route` | ✅ | ⏳ Phase 5 |
| `myszkowski` | ✅ | ⏳ Phase 5 |
| `polybius` | ✅ | ⏳ Phase 5 |
| `quagmire` | ✅ | ⏳ Phase 5 |
| `procedural` | ✅ | ⏳ Phase 8 (recipe enumerator) |

Kinds that validate in the DSL but lack a dispatcher translation fail
*admissibility* (not DSL validation), with a clear pointer at
`_SUPPORTED_KINDS` in the rejection reason.

---

## 3. Three worked examples

### 3.1 Example A — Identity smoke test

The simplest spec: pass CT through, score, return.

```json
{
  "hypothesis_id": "T-SMOKE-001",
  "pipeline": [{"kind": "identity", "alphabet": "AZ", "params": [], "recipe_id": null}],
  "crib_alignment": "direct_positional",
  "scoring": "composite",
  "null_baseline": null,
  "information_gain_bits_estimate": 0.0,
  "success_criteria": {},
  "kill_criteria": {},
  "compute_budget_cpu_minutes": 1,
  "checkpoint_every_sec": 60,
  "assumption_bundle": ["H1_direct_positional"],
  "notes": "Smoke test: identity → CT → score"
}
```

Running this via `execute()`:

- `total_tested = 1`
- `best_candidate.candidate_pt = CT` (unchanged)
- `best_candidate.crib_score = 2` (K4 self-encrypts at positions 32, 73)
- `universe_hash` stable across reruns
- `eliminated_claim = None` (identity is the degenerate case; the
  dispatcher does not fabricate an elimination from a one-config run)

### 3.2 Example B — Periodic Vigenère thematic keyword sweep

The canonical shape a theorist might emit for
"try every English-thematic keyword under periodic Vigenère":

```json
{
  "hypothesis_id": "T-VIG-THEMATIC",
  "pipeline": [
    {
      "kind": "vigenere",
      "alphabet": "AZ",
      "params": [
        {"name": "keyword", "values": ["PALIMPSEST", "ABSCISSA", "KRYPTOS", "LANGLEY", "CIA", "BERLIN", "CLOCK"], "cardinality_cap": 10000}
      ],
      "recipe_id": null
    }
  ],
  "crib_alignment": "direct_positional",
  "scoring": "composite",
  "compute_budget_cpu_minutes": 5,
  "assumption_bundle": ["H1_direct_positional", "single_layer_additive"],
  "notes": "Thematic keyword sweep, single-layer periodic Vigenere on carved 97-char CT"
}
```

Running via `execute(spec, parallel=False)`:

- `total_tested = 7`
- `total_stored = 0` (none crosses STORE_THRESHOLD=10)
- `best_score = 2.0` (self-encrypts; no keyword produces better on raw CT)
- `eliminated_claim` populated: "Spec T-VIG-THEMATIC (...) tested 7
  configurations; none exceeded STORE_THRESHOLD=10..."
- Dispatcher **rejects** the spec if `exhaustion_log.json` contains an
  entry tagged `polyalphabetic/vigenere`, surfacing as an advisory
  admissibility reason. Callers can explicitly confirm and re-run
  (a Phase 5 tool will add `--force` semantics).

### 3.3 Example C — Two-layer columnar + Beaufort

A hypothesis with non-trivial Cartesian product:

```json
{
  "hypothesis_id": "T-COMPOSE-001",
  "pipeline": [
    {
      "kind": "columnar",
      "alphabet": "AZ",
      "params": [
        {"name": "width", "values": [5, 6, 7], "cardinality_cap": 10000},
        {"name": "col_order", "values": [[0,1,2,3,4], [4,3,2,1,0], [2,0,4,1,3]], "cardinality_cap": 10000}
      ],
      "recipe_id": null
    },
    {
      "kind": "beaufort",
      "alphabet": "AZ",
      "params": [
        {"name": "keyword", "values": ["KRYPTOS", "BERLIN", "CLOCK"], "cardinality_cap": 10000}
      ],
      "recipe_id": null
    }
  ],
  "crib_alignment": "post_transposition",
  "scoring": "composite",
  "compute_budget_cpu_minutes": 10,
  "assumption_bundle": ["two_layer_additive_after_transposition"],
  "notes": "Columnar (peel outer) then Beaufort (peel inner). Cardinality = 3 × 3 × 3 = 27."
}
```

`expected_cardinality() == 27`. The dispatcher builds 27 work items,
dispatches via `multiprocessing.Pool(cpu_count()-2)` when parallelism
would pay (by default: ≥10 work items AND not in pytest), kernel-scores
each candidate, aggregates, and emits one `JobResult`.

Note the `col_order` param encodes the full column permutation explicitly.
Sweeping all permutations of width W is `W!` which explodes quickly —
theorists enumerate a motivated subset rather than letting the
cardinality cap enforce a silent truncation.

---

## 4. Admissibility pre-flight (brief §6.2)

The dispatcher's `check_admissibility(spec, exhaustion_log)` returns
`(admissible: bool, reasons: list[str])`. Reasons include:

| Reason class | Source |
|---|---|
| `spec invalid: <dsl error>` | `HypothesisSpec.validate()` |
| `pipeline[N]: kind 'X' has no dispatcher translation` | `_kind_has_translation()` |
| `expected_cardinality N exceeds budget ...` | cardinality × budget × per-minute cap |
| `exhaustion overlap: N prior entries already cover ...` | exhaustion_log.json family substring match |
| `translation error: <DispatcherError>` | per-layer translator (e.g. KA alphabet, invalid perm) |

An admissibility rejection short-circuits: `total_tested=0`,
`best_candidate=None`, `admissibility_verdict="rejected"`,
`admissibility_reasons=[...]`. The caller receives a `JobResult`
regardless (no exceptions raised from `execute()` for admissibility
failures), so log / ledger paths have a single unified shape.

---

## 5. Kernel overrule on this path (brief §6.3 policy 4)

Every candidate returned by the worker function is scored by
`kryptos.kernel.scoring.aggregate.score_candidate` — the canonical
kernel scoring path. The worker does not self-report
`crib_score` / `bean_passed`; those fields are populated directly from
the `ScoreBreakdown` returned by the kernel.

When the dispatcher's result is converted to a `WorkerContract` via
`job_result_to_worker_contract`, the Phase 3
`_verify_against_kernel` runs again on the resulting contract. Both
kernel checks use the same canonical scoring path, so the conversion
is idempotent. The adversarial battery in Phase 3 covers the
worker-self-report attack surface; the dispatcher simply does not
expose that attack surface in the first place.

---

## 6. Checkpointing, parallelism, artifacts

### 6.1 Artifacts

Every `execute()` call writes `result.json` under
`results/dsl_jobs/<hypothesis_id>_<spec_hash>/`. The file contains:

- `manifest`: the `JobResult.to_dict()` (metadata)
- `spec`: the full `HypothesisSpec.to_dict()`
- `all_results`: the per-config results returned by the worker

`artifact_root` is overridable for tests (we passed `tmp_path` through
in every dispatcher test).

### 6.2 Parallelism

Default: `parallel=None` → auto-decide (serial for <10 items, parallel
otherwise). When `parallel=True`, a `multiprocessing.Pool` of
`workers=max(1, cpu_count()-2)` processes is used. When
`PYTEST_CURRENT_TEST` is set, the auto-decision forces serial to keep
tests deterministic. Tests explicitly pass `parallel=False` for full
determinism.

### 6.3 Checkpointing

Phase 4 does not implement per-spec in-process checkpointing. The
`artifact_root` write happens atomically after the whole spec completes.
For the cardinality budgets typical of DSL specs (≤10^4 configs at
~10^5 configs/min), wall clock is well under 10 minutes and
checkpointing would be premature. **If a future spec reaches
`compute_budget_cpu_minutes >= 60`**, add per-chunk checkpointing via
`kryptos.kernel.campaigns.two_layer.checkpoint` — the interface already
exists, just call it from the dispatcher's work-item loop. Placeholder
field `JobResult.checkpoint_path` is reserved for that use.

---

## 7. Acceptance criteria (brief §6.6)

| Criterion | Status |
|---|---|
| `kryptosbot/hypothesis_dsl.py` exists with full type coverage | ✅ |
| `kryptosbot/job_dispatcher.py` exists and runs an end-to-end trivial spec | ✅ (identity + vigenere both verified) |
| Controller can dispatch via DSL and produces kernel-verified results | ✅ (via `job_result_to_worker_contract`; default flow unchanged per §6.6) |
| Existing SDK-worker path is unchanged (backward compatible) | ✅ (no edits to `_dispatch_theories`) |
| ≥15 new tests, all green | ✅ (78) |
| `docs/maturation/phase_04_report.md` documents DSL schema with 3 worked examples | ✅ (this file, §2 and §3) |

---

## 8. Deferred to later phases

| Item | Phase |
|---|---|
| KA alphabet / keyword_mixed alphabet support on Vigenere family | 5 |
| Full translation for `rail_fence`, `route`, `myszkowski`, `polybius`, `quagmire` | 5 |
| Procedural recipe translation (`kind="procedural"`) | 8 |
| Null-baseline calibration populating `best_p_value_vs_null` | 6 |
| Per-chunk checkpointing via `campaigns.two_layer.checkpoint` integration | later (any spec breaching 60 min budget) |
| Controller's `_dispatch_theories` routing theories with `dsl_spec` through the dispatcher by default | future session (not blocking) |
| `information_gain_bits_realized` computation based on actual null p-values | 6 |
| MCP tools `submit_hypothesis_spec`, `poll_job`, `query_exhaustion`, etc. | 5 |
| Self-test against K1/K2/K3 using the DSL | 7 |

None of these are regressions introduced by Phase 4; all are follow-up
work the brief explicitly assigned to later phases.

---

## 9. Changed files summary

```
A  kryptosbot/hypothesis_dsl.py                   (398 lines; DSL + validator)
A  kryptosbot/job_dispatcher.py                   (557 lines; admissibility + dispatch + verify)
A  kryptosbot/tests/test_hypothesis_dsl.py        (42 tests)
A  kryptosbot/tests/test_job_dispatcher.py        (36 tests)
M  kryptosbot/controller.py                       (+ optional `dsl_spec` in theorist prompt)
A  docs/maturation/phase_04_report.md             (this file)
```

No change to the kernel, the default controller dispatch path, the
campaign runner, the site builder, the API server, or any production
path. The DSL is additive infrastructure — it sits alongside the
existing SDK-worker path, available to future controller refactors.
