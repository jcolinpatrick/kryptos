# Framework Maturation — Phases 1-9 Summary

**Period:** 2026-04-20 through 2026-04-21 (7 sessions)
**Brief:** `docs/maturation/phase_00_preflight.md` (and the
original maturation brief delivered in session A)
**Status:** Complete. Phase 7 stop-condition passed.

This document is the handoff per brief §15. Every phase, every
artifact, every test delta, every behavior change.

---

## 1. One-paragraph summary

The framework has moved from *"research harness with good hygiene"*
to *"production-quality cryptanalytic system"*. The three
architectural changes with the largest expected effect on solve
probability are in place: **DSL + dispatcher** (28-core compute now
reachable from agents), **calibrated null baselines** (p-value reasoning
replaces raw scores), and **self-test harness** (K1/K2 rediscoverable
in bounded cycles — the brief's §9.3 stop condition passed). The
remaining phases were hygiene, a new MCP surface, a procedural
enumerator, and a doc refresh. No production behaviour regressions;
the default controller cycle is unchanged. See §3 below for the full
phase-by-phase breakdown.

---

## 2. Headline numbers

| Metric | Start (pre-Phase-1) | End (post-Phase-9) | Delta |
|---|---|---|---|
| `tests/` passing | 1521 | 1525 | +4 |
| `kryptosbot/tests/` passing | 364 | 570 | **+206** |
| `kryptos doctor` status | 17 PASS + 1 FAIL (stale `bean_count`) | 20 PASS / 0 FAIL | +2 checks, 0 fails |
| New modules under `kryptosbot/` | — | 6 (`hypothesis_dsl`, `job_dispatcher`, `dsl_tools`, `null_baselines`, `procedural_enumerator`, `self_test`) | +6 |
| New MCP tools exposed | — | 8 DSL tools + 3 deprecations | +8 / −3 |
| Null-baseline distributions calibrated | 0 | 5 (committed manifest) | +5 |
| Procedural recipes in structured source | 0 | 17 (12 DSL-translatable + 5 physical-only) | +17 |
| Phase-specific maturation commits | 0 | 7 (plus 1 auto-commit + 1 WIP pre-maturation) | — |

Phase 7 falsification test: **K1 and K2 rediscovered within 20 cycles
(actual: 15 and 17 respectively)**. K3 not in brief's stop-condition
list; single-layer coverage insufficient for K3's double-columnar
structure — documented as a known gap.

---

## 3. Phase-by-phase

### Phase 1 — Legacy-surface quarantine (commit `fdc4eea`)

- Quarantined `kryptosbot/campaign_v2.py` + `worker.py` to
  `kryptosbot/_archive/` with `ImportError` stubs at original paths
  (both imported modules that no longer existed).
- Renamed `scripts/EXHAUSTION.json` → `.RETIRED`.
- Fixed `src/kryptos/cli/doctor.py` stale `bean_count` check
  (asserted `== 21`; real value is 242 for 15+ weeks).
- `kryptosbot/RUNBOOK.md` replaced with stub pointing to ORIENT.md;
  `.gitignore` unignored so the stub lands in the repo.
- Added `tests/test_doctor.py` — zero-failures regression guard.

Test delta: `tests/` 1521 → 1522 (+1). doctor: 1 FAIL → 0 FAIL.

### Phase 2 — Retired-constant relocation (commit `6db2e20`)

- Created `src/kryptos/kernel/retired/` namespace.
- Moved `NULL_PALETTE`, `CONSENSUS_NULL_POSITIONS`,
  `BEAUFORT_KEYSTREAM_AT_CRIBS` out of
  `kryptos.kernel.constants` into the retired namespace.
- 4 live-code importers migrated (`kryptos.kernel.scoring.compliance`,
  `kryptos.kernel.constraints.stego`, `kryptosbot.polybius_scorer`,
  `kryptosbot.constants`).
- 8 test files migrated with inline justifying comments.
- Added `tests/test_retired_usage.py` — AST-based CI guard with
  11-entry allow-list.
- `kryptosbot/critic.py` docstrings updated to cross-reference the
  new import-level guard.

Test delta: `tests/` 1522 → 1525 (+3 retired-usage tests).

### Phase 3 — Kernel-overrule adversarial test battery (commit `941371a`)

- `WorkerContract` gained `bean_variant: Optional[str]`.
- `_verify_against_kernel` refactored into named `_BEAN_VARIANTS` tuple
  (fixed order: vigenere → beaufort → variant_beaufort; first PASS
  records variant name on the contract).
- Added `_safe_int` / `_safe_float` defensive coercion helpers.
- 35-test adversarial battery in
  `kryptosbot/tests/test_verify_against_kernel_adversarial.py` across
  9 categories (length / case-whitespace / crib-fakes / variant
  selection / empty+nonzero / unicode smuggling / numeric type
  confusion / nested JSON / conflicting self-reports) + 2 property
  tests (400 adversarial MC samples each).
- **100% line coverage** on `_verify_against_kernel` (67/67 lines),
  `_safe_int`, `_safe_float`.
- `coverage==7.13.5` pinned in `requirements.txt`.

Test delta: `kryptosbot/tests/` 364 → 399 (+35).

### Phase 4 — Hypothesis DSL + job dispatcher (commit `af1eec6`)

**The architectural pivot.** Worker agents no longer write ad-hoc
cryptanalytic code in scratch directories.

- `kryptosbot/hypothesis_dsl.py` (398 lines): `ParamRange`,
  `CipherLayer`, `NullBaselineSpec`, `HypothesisSpec` dataclasses
  with runtime validation tied to frozenset registries of valid
  CipherKind × AlphabetKind × CribAlignment × ScoringMode ×
  NullBaselineMethod. Canonical JSON serialization with
  order-independent `spec_hash`. `validate_hypothesis_spec()`
  returns `ParseResult<HypothesisSpec>` with explicit errors.
- `kryptosbot/job_dispatcher.py` (557 lines): admissibility pre-flight
  → cartesian-product enumeration → per-layer translation to kernel
  `TransformConfig` → `multiprocessing.Pool` dispatch →
  `score_candidate` kernel verification → aggregate to `JobResult`.
  Deterministic `universe_hash`. Artifact JSON at
  `results/dsl_jobs/`. `job_result_to_worker_contract` helper runs
  the Phase-3 verifier on the output.
- Supported kinds Phase 4: `identity`, `vigenere` (AZ),
  `beaufort` (AZ), `variant_beaufort` (AZ), `columnar`, `atbash`.
- 78 tests (42 DSL + 36 dispatcher). Brief minimum was 15.
- Controller integration minimal (theorist prompt mentions optional
  `dsl_spec`; default flow unchanged per brief §6.6 backward-compat).

Test delta: `kryptosbot/tests/` 399 → 477 (+78).

One DSL bug surfaced + fixed during tests:
`HypothesisSpec.from_dict` used `int(v or default)` on
`compute_budget_cpu_minutes` — a literal 0 is falsy, bypassing
validation. Fixed with `_coerce_int` / `_coerce_float` helpers.

### Phase 5 — MCP tool surface redesign (auto-commit `e1afbff`)

- 3 noise tools in `kryptosbot/k4_tools.py` emit
  `DeprecationWarning`: `hill_climb`, `try_keyword_sweep`,
  `swap_and_test`. All remain importable + registered per brief
  §7.1 backward-compat.
- `kryptosbot/dsl_tools.py` (488 lines): 8 new DSL-oriented tools
  returning `{status, data, provenance}` envelope with kernel
  commit hash + phase + assumption_bundle:
  - `submit_hypothesis_spec` (background dispatch + job_id)
  - `poll_job`
  - `query_exhaustion`
  - `compute_null_baseline`
  - `score_candidate_canonical`
  - `get_procedural_recipe`
  - `enumerate_admissible_transforms`
  - `request_compute_budget_estimate`
- Background job registry (`_JOBS` dict + lock) with race-hardening
  for test-reset mid-flight.
- Worker prompt updated in `kryptosbot/controller.py` to direct
  DSL-first flow. Scratch policy narrowed to interpretation-only.
- 35 new tests. Brief minimum was 24 (8 tools × 3).

Test delta: `kryptosbot/tests/` 477 → 512 (+35).

### Phase 6 — Calibrated null baselines (commit `61fa7d9`)

- `kryptosbot/null_baselines.py` (408 lines): `NullDistribution`
  dataclass with `sorted_scores` + empirical/parametric tails.
  - **Exact Binomial(24, 1/26)** tail for `crib_score × random_text`
    (closed form; reliable below the 1/N empirical floor).
  - **Normal** tail for `ngram_score` (CLT on ~94 quadgram
    log-probs summed per PT).
  - Empirical + 1/N upper bound fallback for everything else.
- `calibration_stale(dist)` detects kernel-commit drift (tolerant
  of 'unknown' on either side).
- `ScoreBreakdown.p_value_breakdown: Optional[Dict[str, float]]`
  field; `score_candidate(..., include_p_values=True)` populates it.
- `kryptosbot/alerts.py`: SIGNAL and BREAKTHROUGH now gate on
  `p_value <= 1e-6`. **Fails open** to legacy crib-only gating on
  cache miss with a WARNING log — framework never goes silent on a
  high score.
- `scripts/_infra/calibrate_null_baselines.py` batch runner (full
  5-distribution calibration in 17.8 s).
- `null_baselines/manifest.json` committed (per-distribution
  summary); 3.4 MB full cache gitignored under
  `results/null_baselines/`.
- `dsl_tools.compute_null_baseline` rewired from Phase-5 stub.
- 17 new tests. Empirical mean for `crib_score × random_text`:
  **0.9237 vs theoretical 0.9231** (0.06% deviation).

Test delta: `kryptosbot/tests/` 512 → 530 (+18 net).

### Phase 7 — Self-test harness (commit `63dea03`)

**The brief's falsification test.**

- `kryptosbot/self_test.py` (364 lines): `Panel` dataclass for
  K1/K2/K3, `ct_override()` contextmanager, per-panel pseudo-crib
  scoring, strategy generators (Quagmire III for K1/K2,
  single-layer columnar for K3).
- Dry-run mode (no API, deterministic) fully implemented.
- Real-API mode documented but deliberately not executed (~$1.30
  per panel vs $50 brief ceiling; requires panel-specific crib
  registry + controller self_test_mode flag; operational plan in
  report §5).
- CLI: `--panel {k1|k2|k3|all} --mode {dry-run|real} --cycles N
  --report-path PATH`.
- Independent kernel-sanity check runs BEFORE strategy search so a
  kernel regression surfaces as `KERNEL REGRESSION`, not "framework
  self-test failure".

**Dry-run results** (verbatim; brief §9.3 no-spin requirement):

| Panel | Discovered? | Cycles | Via |
|---|---|---|---|
| **K1** | ✅ **yes** | **15** | `keyword=PALIMPSEST, indicator=K` (Quagmire III) |
| **K2** | ✅ **yes** | **17** | `keyword=ABSCISSA, indicator=K` (Quagmire III) |
| **K3** | ❌ no | — | single-layer coverage insufficient |

Zero false-positive breakthroughs across all three panels.
**Brief §9.3 stop condition PASSED** (K1-or-K2 failure would stop
progression; both solved).

Honest finding: Phase 7 went around the DSL dispatcher for K1/K2
because the dispatcher's `_translate_layer` only supports AZ
alphabet for Vigenère family (Phase 4 §6.5 explicitly deferred KA).
Called out as a known gap in the Phase 7 report §6.1.

Test delta: `kryptosbot/tests/` 530 → 549 (+19).

### Phase 8 — Procedural hypothesis enumerator (commit this session)

- `docs/procedural_recipes.json` (17 recipes: 12 DSL-translatable +
  5 physical-only). Schema carries recipe_id, title, anomaly_id,
  procedure, tested_status, priority, known_eliminations, and
  dsl_template.
- `kryptosbot/procedural_enumerator.py` (336 lines):
  `ProceduralRecipe` dataclass, recipe loader (rejects duplicates),
  `recipe_to_spec()` (spec validation + failure logging),
  `enumerate_all_procedural()` (filters physical_only / closed-anomaly
  / bundle-overlap / budget-exhaustion), priority ordering
  (high → medium → low → baseline), CLI with `--dry-run` / `--sweep`.
- 21 new tests.

**First-sweep results** (brief §10.5): 12 admissible specs dispatched;
8 ran to completion (all returned `[eliminated]`); 4 rejected at
dispatcher admissibility due to exhaustion-log overlap (Phase-4
advisory heuristic working as designed). Best score **4.0** on
`P-F1-1` (misspelling-derived Vigenère keys), well below SIGNAL=18.

Test delta: `kryptosbot/tests/` 549 → 570 (+21).

### Phase 9 — Documentation refresh (commit this session)

- `kryptosbot/ORIENT.md` **NEW** (160 lines). One-page operator
  onboarding: mission, three commands, where truth lives,
  preflight-skip consequences, 5 common failure modes + command
  catalogue + decision tree.
- `kryptosbot/ARCHITECTURE.md` updated: 8 new file-map rows,
  refreshed preserved-components, new "DSL + Dispatcher + Null
  Baselines" major section (~60 lines with ASCII pipeline diagram).
- `CLAUDE.md` surgical: pre-flight gained steps 9-10
  (ORIENT pointer + self-test fitness check); Interpreting Scores
  gained p-value-gate paragraph; Reference Documents gained 3 new
  entries.
- `MEMORY.md` gained one Pointers entry + refreshed footer.

No code changes; no test delta.

---

## 4. Deferred items (flagged across the phases)

The brief's §13 explicitly said "this brief does not do" the
following — they remained out of scope:

- K4 solution itself (Phase 7's stop-condition test was about
  framework fitness, not K4).
- Full KA-alphabet dispatch support (Phase 4 AZ-only; Phase 7
  documented the gap).
- Full `matched_variant_family` for non-Vigenère families (Phase 6
  did AZ-Vigenère as demonstrator).
- Bulk-rewriting 72 `scripts/` files that import retired constants
  from old path (Phase 2 explicit scope decision; failing ImportError
  when re-run is acceptable for archived experiments).
- Real-API self-test execution (Phase 7 documented operational plan;
  requires ~$1.30-$5 per panel and prerequisite wiring).
- `calibration_stale()` refinement to be sensitive only to scoring
  path changes, not every kernel commit (Phase 6 flagged; currently
  causes manifest rewrite each phase commit).
- Remaining ~18 procedural recipes (Phase 8 ported 17 of the ~35
  catalogued; remaining have less clear DSL translations).

None of these invalidate Phases 1-9 acceptance. They are each
documented in the owning phase's report.

---

## 5. Commit log (local, unpushed)

```
63dea03 maturation phase 07: self-test harness (K1/K2 rediscovered)
61fa7d9 maturation phase 06: calibrated null baselines
e1afbff [auto] Update 1 doc(s),4 other file(s)        ← Phase 5 content
af1eec6 maturation phase 04: hypothesis DSL + job dispatcher
941371a maturation phase 03: kernel-overrule adversarial test battery
6db2e20 maturation phase 02: retired-constant relocation
fdc4eea maturation phase 01: legacy surface quarantine
5ad398d wip: pre-maturation baseline (day 5/6/7 pantheon, site-builder tests, self_heal)
```

Plus Phase 8 + Phase 9 commits landing with this handoff.

---

## 6. Per the brief's §15 handoff contract

1. ✅ Summary document in place (`docs/maturation/SUMMARY.md`, this file).
2. ✅ Self-test run on K1/K2/K3 (dry-run mode; results pasted in §3
   above and in `docs/maturation/phase_07_self_test_report.md`).
   Real-API mode deliberately not executed per the brief's "operator
   commissions deliberately" guidance.
3. ✅ `MEMORY.md` pointer section updated (see Phase 9 report §5).
4. ⏸️ **STOP**. Per brief §15 step 4: do not start a new research
   campaign on the maturated framework without explicit user
   approval. The framework is now capable of producing honest
   results; whether to *use* that capability against K4 is a
   separate decision the operator makes.

---

## 7. Reading order for the next operator

1. `CLAUDE.md` — operational doctrine.
2. `MEMORY.md` — live research state.
3. This file (`docs/maturation/SUMMARY.md`) — what changed and why.
4. `kryptosbot/ORIENT.md` — one-page operator onboarding for the
   multi-agent loop.
5. Per-phase reports as needed: `docs/maturation/phase_NN_report.md`.

And run the pre-flight (`kryptos doctor` + `session_briefing.py` +
`pytest kryptosbot/tests/`) before touching anything.
