# PR2 — Deterministic Coverage Scheduler (design)

**Date:** 2026-05-25
**Status:** approved design, pre-implementation
**Builds on:** PR1 (synthetic-profile registry + coverage-audit artifact, commit `ea6ebb8`)
**Scope owner:** kryptosbot synthetic-profile coverage subsystem

---

## 1. Problem

PR1 made synthetic-profile coverage failure **observable**: a `SyntheticProfile`
declares a structural obligation (e.g. `T1_SERPENTINE_QUAGMIRE` requires a
`quagmire` layer, `variant=quagmire_iii`, `period_keyword=SERPENTINE`), and the
`coverage_audit` collector writes a `coverage_report.json` recording exactly why
the obligation was or was not met. The PR1 end-to-end smoke confirmed the T1
postmortem failure mode reproduces live: the LLM theorist emitted SERPENTINE as a
*route* layer and a Quagmire *IV*, but never under the pinned
`quagmire_iii / period_keyword` axis, so the report correctly recorded
`obligation_not_emitted`.

PR1 **detects** the gap. It does not **close** it. Closing the gap currently
depends on the LLM theorist happening to propose the right spec — exactly the
caprice the T1 postmortem identified as the failure mode.

## 2. Goal

Add a **deterministic coverage scheduler**: when explicitly enabled, it builds and
admits an obligation-satisfying spec for each available profile, independent of the
LLM, so the obligation is closed by construction rather than by chance.

The `--coverage-scheduler-enabled` flag (parsed-but-inert in PR1, recorded only in
`extra_notes`) becomes active.

## 3. Closure semantics (decided)

"Obligation closed" means **emitted + admissible**: the scheduler proves the
obligation spec is generated AND passes the dispatcher's admissibility / translation
acceptance gate, then **stops before kernel execution**. It never scores against a
ciphertext.

Rationale: the T1 gap was about **emission/admission**, not scoring. Running the
obligation spec through the kernel would mean executing against the real K4
ciphertext (synthetic profiles carry a mechanism contract, not a synthetic
ciphertext) — which collides with the standing "no real K4 search" rule. The
scheduler therefore stops at the admissibility boundary. This is faithful to what
PR2 needs to prove and keeps the no-execution / no-real-K4 guarantee intact.

A synthetic-ciphertext-bearing variant (real recovery, "satisfied via scoring") is
explicitly **out of scope** and noted as possible future work.

## 4. Closing-spec source (decided)

Each `available` profile carries an **explicit, auditable `closing_spec`
template** — a full `HypothesisSpec` (layers + `NullBaselineSpec` + compute budget)
whose obligation-relevant axis is pinned to the required value. The scheduler
dispatches the template verbatim through admissibility.

Rejected alternative: scheduler synthesizing a minimal spec from the obligation +
defaults. Rejected because the closing spec would be implicit/generated and harder
to audit, which is contrary to the project's anti-laundering discipline. An explicit
template keeps the obligation and its closing spec visibly consistent.

## 5. Integration approach (decided): standalone scheduler phase

A new `kryptosbot/coverage_scheduler.py` runs as a **distinct phase** in
`run_controller`, taken *instead of* the LLM cycle when
`--synthetic-profile` AND `--coverage-scheduler-enabled` are both set.

Rejected alternatives:
- **B (seed injection + admissibility-only dispatch mode):** would touch BOTH cycle
  loops (the documented dual-loop foot-gun) and the dispatch path, and still spin up
  the LLM theorist unnecessarily. Higher blast radius.
- **C (static self-consistency only):** would not exercise the real dispatcher
  acceptance path; weakest guarantee.

Approach A runs a genuine admissibility check through the real dispatcher, preserves
the no-execution guarantee, avoids the dual-loop foot-gun, and is independently
testable.

## 6. Components

### 6.1 `synthetic_profiles.py` — profile extension

- Add optional field `closing_spec: Optional[dict] = None` to `SyntheticProfile`
  (DSL `HypothesisSpec` JSON/dict form, round-trips via `HypothesisSpec.from_dict`).
- `__post_init__` invariant additions:
  - `available` profile MUST carry a non-empty `closing_spec`.
  - `blocked` profile MUST NOT carry a `closing_spec`.
- New registry-level self-consistency check, callable as a function and exercised in
  tests: for every `available` profile, the parsed `closing_spec` MUST satisfy every
  one of the profile's obligations under `ParameterObligation.matches` (reusing the
  PR1 matcher and the PR1 `_layer_to_record` flattening so obligation-vs-spec
  matching uses one code path). A profile whose template fails to close its own
  obligation is a hard error.
- Populate `closing_spec` for the three available profiles
  (`T1_SERPENTINE_QUAGMIRE`, `T1_BERLINKLOCK_COLUMNAR`, `T1_ABSCISSA_ROUTE`).
  `T1_TAPE_K3PT` stays `blocked` with no `closing_spec`.

### 6.2 `coverage_scheduler.py` — new module

Public entry:

```python
def run_coverage_schedule(
    profile: SyntheticProfile,
    collector: CoverageAuditCollector,
    *,
    project_root: Path,
) -> CoverageReport: ...
```

Behavior:
1. Refuse `blocked` profiles (return a report whose obligations are unmet with the
   blocked reason) — mirrors PR1's launch refusal.
2. Take the profile's single `closing_spec` and run a small helper
   `check_spec_admissibility(spec)` **once** — it performs only the pre-kernel
   preamble of `job_dispatcher.execute`: `HypothesisSpec.from_dict` →
   procedural-layer expansion → `check_admissibility(...)`. Returns
   `(verdict, reasons)`. It does **not** call `execute()` or the kernel. (A profile
   has exactly one `closing_spec`; the §6.1 invariant guarantees that single spec
   satisfies every obligation the profile declares, so admissibility is checked once,
   not per obligation. Each obligation is then evaluated against that emitted+admitted
   spec by the PR1 collector in step 4.)
3. Record through the PR1 collector:
   - `collector.record_emitted_spec(...)` for the closing spec (so the obligation
     matcher sees it).
   - `collector.record_dispatcher_outcome(..., admissibility_verdict=verdict,
     admissibility_only=True, total_tested=0)` — the new `admissibility_only` flag
     (see 6.3) marks intentional no-execution.
4. Build and return the report. Never executes the kernel.

The helper `check_spec_admissibility` lives in `coverage_scheduler.py` and calls the
existing public `job_dispatcher` pieces; `job_dispatcher` is not modified beyond, at
most, exposing the procedural-expansion call if it is not already importable. (If
extraction is needed it is a pure refactor with no behavior change, guarded by the
existing dispatcher tests.)

### 6.3 `coverage_audit.py` — audit extension

- New sentinel `REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE = "emitted_and_admissible"`.
- `DispatcherOutcomeRecord` gains `admissibility_only: bool = False`.
- `_evaluate_obligation`: when a matching spec has a dispatcher outcome with
  `admissibility_verdict == "ok"` and `admissibility_only is True` and
  `total_tested == 0`, the cause is `EMITTED_AND_ADMISSIBLE`, which `_aggregate_pass`
  treats as **satisfied** (distinct from PR1's `halted_before_dispatch`, which
  remains the cause for an `ok`-but-no-record dry-run/halt with no
  `admissibility_only` marker).
- `SCHEMA_VERSION` bumped to `coverage_report.v2`. Migration note added to the module
  docstring: v2 adds the `emitted_and_admissible` cause and the
  `admissibility_only` field; v1 parsers remain valid for v1 artifacts.

### 6.4 `run_controller.py` — wiring

- When `--synthetic-profile` AND `--coverage-scheduler-enabled`: build the collector
  (as in PR1), call `coverage_scheduler.run_coverage_schedule(...)`, write the report
  via the existing `resolve_report_path` + `write_report` path, and **skip the LLM
  cycle entirely** for that run.
- `--coverage-scheduler-enabled` set WITHOUT `--synthetic-profile` becomes an explicit
  `parser.error(...)` (PR1 left it merely inert).
- Ledger isolation unchanged: the run is still forced onto
  `db/synthetic_profiles/<profile_id>.sqlite` via the existing
  `derive_synthetic_profile_ledger_path`. Mutual-exclusivity rules (vs bench / hcc
  audits) unchanged.

## 7. Safety invariants (asserted in code + tests)

- Never calls `job_dispatcher.execute()` or any kernel scoring path.
- Never touches the real / default ledger (`db/theory_ledger.sqlite`).
- No LLM / Agent SDK / API call on the scheduler path.
- Refuses `blocked` profiles.
- Refuses to run if the problem context is real-K4.

## 8. Testing

New `kryptosbot/tests/test_coverage_scheduler.py` (plus additions to the existing
PR1 test files where appropriate):

1. **Registry self-consistency** — every `available` profile's `closing_spec`
   satisfies every obligation it declares; `blocked` profiles carry no
   `closing_spec`; `available` profiles carry one.
2. **Happy path** — `run_coverage_schedule(T1_SERPENTINE_QUAGMIRE, ...)` yields a
   report with the obligation cause `emitted_and_admissible` and `pass == True`.
3. **Admissibility rejection** — a deliberately malformed closing spec (e.g. budget
   exceeded or untranslatable) is reported as `emitted_but_admissibility_rejected`,
   `pass == False`.
4. **Blocked profile refused** — `T1_TAPE_K3PT` returns an unmet report citing the
   blocked reason; no admissibility call.
5. **Real-K4 context refused** — scheduler refuses when the problem context is
   real-K4.
6. **No-execution guarantee** — patch/spy `job_dispatcher.execute` and the kernel
   scoring entry; assert they are never called during a scheduler run.
7. **Schema** — report `schema_version == "coverage_report.v2"`; `admissibility_only`
   present on scheduler dispatcher outcomes.
8. **Ledger isolation** — real ledger mtime/contents untouched after a scheduler run;
   synthetic ledger path used.
9. **CLI** — `--coverage-scheduler-enabled` without `--synthetic-profile` errors;
   `--help` advertises the now-active flag.

## 9. Explicitly NOT in PR2 (scope guard / YAGNI)

- No kernel execution or scoring.
- No synthetic ciphertext per profile (no "satisfied via scoring").
- No `(tape_seed × null_positions × null_rule × alphabet)` finite-tape search model.
- `T1_TAPE_K3PT` remains `blocked`.
- No LLM theorist involvement on the scheduler path.
- **No K4-solve capability is claimed.** This is deterministic coverage tooling for
  synthetic-profile runs against an isolated ledger; it makes no statement about the
  real K4 plaintext or method.
