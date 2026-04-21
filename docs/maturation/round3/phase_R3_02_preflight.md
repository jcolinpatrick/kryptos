# Phase R3-2-00 — Pre-flight Report

**Date:** 2026-04-21
**Brief:** R3-2 commissioning instruction (from operator)
**Design docs inherited:** `CURRENT_WORKER_PATH.md`, `DSL_CUTOVER_CONTRACT.md` (auto-authoritative on `_SUPPORTED_KINDS` per §1.2)
**Goal:** establish a clean green baseline for the R3-2 cutover against commit `02442df` (R3-0.5 exit).

---

## 1. Baseline capture

### 1.1 `kryptos doctor`

```
PYTHONPATH=src python3 -m kryptos doctor
```

**All 20 checks PASS.** No FAIL rows.

### 1.2 Core test suite

```
PYTHONPATH=src pytest tests/ -q
→ 1529 passed in 106.29s
```

### 1.3 Kryptosbot test suite

```
PYTHONPATH=src pytest kryptosbot/tests/ -q
→ 725 passed in 18.89s
```

Breakdown relative to R3-0.5 entry (658):
- +22 from R3-0.5-1 (procedural translator)
- +24 from R3-0.5-2 (grille translator)
- +21 from R3-0.5-3 (polybius translator)
- Total: 725

### 1.4 Self-test dry-run at R2 exit settings

```
PYTHONPATH=src python3 -u kryptosbot/self_test.py --panel all --mode dry-run \
    --cycles 20000 --report-path results/self_test/r3_2_baseline.json
```

| Panel | discovered_via    | cycles   | peak_score |
|---|---|---|---|
| k1 | quagmire_iii    | **15**   | 20/20 |
| k2 | quagmire_iii    | **17**   | 20/20 |
| k3 | columnar_double | **9345** | 20/20 |

**K1/15, K2/17, K3/9345** — identical to every prior round's entry and exit. The R3-2 rewire must preserve this throughout the round.

### 1.5 Git baseline

```
HEAD = 02442df maturation round 3.5 complete: DSL completion for procedural, grille, polybius
```

Untracked files carried over from prior rounds (not in R3-2 scope):

- `docs/maturation/round2/K4_RUN_POSTMORTEM.md`
- `f0aac050-...png`
- `scripts/_infra/k4_run_postmortem.py`
- `tests/test_k4_run_dashboard.py`
- `null_baselines/manifest.json` — metadata-only refresh (unmodified stats)

### 1.6 `_SUPPORTED_KINDS` inheritance

```
PYTHONPATH=src python3 -c "
from kryptosbot.job_dispatcher import _SUPPORTED_KINDS
print(sorted(_SUPPORTED_KINDS))
"
→ ['atbash', 'beaufort', 'columnar', 'grille', 'identity', 'polybius',
   'procedural', 'variant_beaufort', 'vigenere']
```

9 kinds. R3-2 does not add or remove kinds — per brief non-goal §5 and DSL_CUTOVER_CONTRACT §1.2 auto-authoritative read. R3-2 consumes whatever `_SUPPORTED_KINDS` contains at implementation time.

---

## 2. Expected-state comparison

Per brief pre-flight:

| Check | Expected | Actual | Match |
|---|---|---|---|
| doctor | 20/0 | 20/0 | ✓ |
| core tests | 1529 | 1529 | ✓ |
| kryptosbot tests | 725 | 725 | ✓ |
| self-test K1 cycles | 15 | 15 | ✓ |
| self-test K2 cycles | 17 | 17 | ✓ |
| self-test K3 cycles | 9345 | 9345 | ✓ |
| HEAD | `02442df` | `02442df` | ✓ |

All seven pre-flight expectations satisfied. **Safe to proceed to R3-2.**

---

## 3. Invariants R3-2 must preserve (from brief critical invariants)

1. K1 dry-run still discovers at cycle 15.
2. K2 at cycle 17, K3 at cycle 9345.
3. R2-5 real-API K1 test still passes.
4. Phase 3 kernel-overrule adversarial battery (35 tests in `test_verify_against_kernel_adversarial.py`) still green.
5. Phase 6 p-value gate still fires on `p ≤ 1e-6`.
6. Matched-family nulls from R2-4 must now actually be consulted (R3-3 verifies).

Each invariant will be checked at R3-2 exit and at R3-3 integration test.

---

## 4. R3-2 target surface (from DSL_CUTOVER_CONTRACT §9 acceptance)

Landing in this phase:

- `TheoryRecord.dsl_spec: dict = field(default_factory=dict)` new field + ledger schema update.
- `WorkerStatus.REJECTED_ADMISSIBILITY = "rejected_admissibility"` new enum value.
- `kryptosbot/contracts.py::validate_theory_proposals` parses and validates `dsl_spec`.
- `kryptosbot/critic.py::TheoryCritic.evaluate` gains Category-A/C check before existing checks, Category-B skip.
- `kryptosbot/controller.py::_dispatch_theories` fan-out by category (DSL_CUTOVER_CONTRACT §2.5).
- `kryptosbot/controller.py::_run_worker` rewritten to use `job_dispatcher.execute()` + `_verify_against_kernel` via `job_result_to_worker_contract`.
- `kryptosbot/controller.py::_run_worker_legacy` kept live for Category B with `tag` parameter.
- `kryptosbot/controller.py::_build_theorist_prompt` updated: `dsl_spec` required for cipher-family theories with example-driven guidance.
- `kryptosbot/alerts.py` / `_run_alerts` match-null keying on `raw_artifacts["dsl_pipeline_kinds"]`.
- Minimum 12 tests covering brief §3.8 scenarios plus 3+ hybrid-split scenarios.

Non-regression target: all 1529 core + 725 kryptosbot tests still green, self-test K1/15 K2/17 K3/9345 unchanged.

---

## 5. Scope budget

Brief says: "if R3-2 grows past ~800 lines of changed code, escalate." Pre-flight surface estimate:

| Area | Est. lines |
|---|---|
| `models.py` — `TheoryRecord.dsl_spec` field + `WorkerStatus.REJECTED_ADMISSIBILITY` enum | ~15 |
| `contracts.py` — DSL validation in `validate_theory_proposals` | ~40 |
| `critic.py` — Category-A/C check with NON_DSL_FAMILIES skip | ~50 |
| `controller.py::_dispatch_theories` fan-out | ~30 |
| `controller.py::_run_worker` DSL rewrite | ~80 |
| `controller.py::_run_worker_legacy` `tag` parameter | ~15 |
| `controller.py::_build_theorist_prompt` DSL contract updates | ~40 |
| `alerts.py` / `_run_alerts` matched-null keying | ~30 |
| `theory_ledger.py` or schema migration for `dsl_spec` column | ~20 |
| Tests | (additive, not counted against the cap) |
| **Subtotal production code** | **~320** |

Well under the 800-line cap. Leaves plenty of headroom for docstrings and error-path elaboration. If the actual delta approaches 500 lines, it's a signal to stop and re-check scope.

---

## 6. Ready to proceed

Starting R3-2 cutover implementation at commit `02442df`.

Order of operations (per DSL_CUTOVER_CONTRACT §5):

1. Land `WorkerStatus.REJECTED_ADMISSIBILITY` and `TheoryRecord.dsl_spec` in `models.py`.
2. Update `validate_theory_proposals` in `contracts.py` to parse/validate the DSL spec.
3. Update `TheoryCritic.evaluate` in `critic.py` with the Category check.
4. Update `theory_ledger.py` to persist `dsl_spec`.
5. Rewrite `_run_worker` in `controller.py` for Category-A DSL dispatch.
6. Refactor `_run_worker_legacy` to accept `tag` parameter.
7. Update `_dispatch_theories` fan-out.
8. Update `job_result_to_worker_contract` to emit `REJECTED_ADMISSIBILITY` (currently emits INCONCLUSIVE).
9. Update `_build_theorist_prompt` to require `dsl_spec`.
10. Wire matched-null keying in alerts.
11. Write ≥12 tests covering brief §3.8 + hybrid scenarios.
12. Run non-regression gauntlet: full suites + self-test + R2-5 real-API check.

*End of R3-2 pre-flight report. Starting cutover implementation.*
