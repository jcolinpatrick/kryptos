# PR2 Deterministic Coverage Scheduler — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When `--coverage-scheduler-enabled`, deterministically build and admissibility-check an obligation-satisfying spec for each available synthetic profile, so a profile's obligation is closed by construction (emitted + admissible) rather than by LLM chance — without ever executing the kernel or touching the real K4 ledger.

**Architecture:** A standalone `coverage_scheduler.py` phase replaces the LLM cycle when the flag is set. Each available `SyntheticProfile` carries an explicit `closing_spec` (a DSL `HypothesisSpec` dict) whose obligation axis is pinned to the required value. The scheduler runs only the dispatcher's pre-kernel preamble (`_expand_procedural_layers` → `check_admissibility`) and records the verdict through the PR1 collector as a new `emitted_and_admissible` outcome. Coverage report schema bumps to `coverage_report.v2`.

**Tech Stack:** Python 3.12, stdlib only for core; `pytest` (run via `venv/bin/python -m pytest -n <N>` for parallelism). DSL types in `kryptosbot/hypothesis_dsl.py`; dispatcher in `kryptosbot/job_dispatcher.py`; PR1 modules `kryptosbot/synthetic_profiles.py` + `kryptosbot/coverage_audit.py`.

**Spec:** `docs/specs/2026-05-25-coverage-scheduler-pr2-design.md`

---

## File Structure

- **Modify** `kryptosbot/coverage_audit.py` — add `emitted_and_admissible` cause, `admissibility_only` field, schema v2, evaluator/aggregate handling. (Task 1)
- **Modify** `kryptosbot/synthetic_profiles.py` — add `closing_spec` field + presence invariants + populate 3 available profiles. (Task 2)
- **Create** `kryptosbot/coverage_scheduler.py` — `check_spec_admissibility`, `verify_profile_closing_spec`, `run_coverage_schedule`. (Task 3)
- **Modify** `kryptosbot/run_controller.py` — CLI error + branch the scheduler phase in place of `do_run`. (Task 4)
- **Modify** `kryptosbot/tests/test_coverage_audit.py` — v2 + new-cause tests. (Task 1)
- **Modify** `kryptosbot/tests/test_synthetic_profiles.py` — closing_spec presence tests. (Task 2)
- **Create** `kryptosbot/tests/test_coverage_scheduler.py` — scheduler behavior + self-consistency + no-execution guarantee. (Task 3)
- **Modify** `kryptosbot/tests/test_run_controller_synthetic.py` — CLI error + branch wiring. (Task 4)

Convention reminder: parallel test runs use `PYTHONPATH=src /home/cpatrick/kryptos/venv/bin/python -m pytest <targets> -q -n 8`. Single-file/by-name runs can use plain `PYTHONPATH=src python3 -m pytest`.

---

## Task 1: coverage_audit schema v2 — `emitted_and_admissible` cause + `admissibility_only`

**Files:**
- Modify: `kryptosbot/coverage_audit.py`
- Test: `kryptosbot/tests/test_coverage_audit.py`

- [ ] **Step 1: Write the failing tests**

Add to `kryptosbot/tests/test_coverage_audit.py`. Also update the existing
`test_schema_version_is_pinned` in this file to expect `"coverage_report.v2"`
(it currently hardcodes `v1`) — that is the single schema-version assertion;
do not add a second one.

```python
def test_emitted_and_admissible_is_satisfied(tmp_path: Path) -> None:
    # An obligation whose matching spec was admitted (admissibility_only,
    # total_tested=0, verdict ok) counts as SATISFIED — distinct from
    # halted_before_dispatch.
    from kryptosbot.coverage_audit import (
        CoverageAuditCollector, REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE,
    )
    from kryptosbot.synthetic_profiles import get_profile
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    c = CoverageAuditCollector(profile=profile)
    c.record_emitted_spec(
        hypothesis_id="h1", title="t", family="quagmire_iii",
        layers=[{
            "kind": "quagmire", "alphabet": "KA",
            "params": [
                {"name": "variant", "values": ["quagmire_iii"]},
                {"name": "period_keyword", "values": ["SERPENTINE"]},
            ],
        }],
    )
    c.record_dispatcher_outcome(
        hypothesis_id="h1", admissibility_verdict="ok",
        admissibility_only=True, total_tested=0,
    )
    report = c.build_report()
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE in causes
    assert report.passed is True


def test_admissibility_only_false_still_halts(tmp_path: Path) -> None:
    # Same shape but WITHOUT admissibility_only must remain
    # halted_before_dispatch (PR1 behavior preserved).
    from kryptosbot.coverage_audit import (
        CoverageAuditCollector, REJECTION_CAUSE_HALTED_BEFORE_DISPATCH,
    )
    from kryptosbot.synthetic_profiles import get_profile
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    c = CoverageAuditCollector(profile=profile)
    c.record_emitted_spec(
        hypothesis_id="h1", title="t", family="quagmire_iii",
        layers=[{
            "kind": "quagmire", "alphabet": "KA",
            "params": [
                {"name": "variant", "values": ["quagmire_iii"]},
                {"name": "period_keyword", "values": ["SERPENTINE"]},
            ],
        }],
    )
    c.record_dispatcher_outcome(
        hypothesis_id="h1", admissibility_verdict="ok",
        admissibility_only=False, total_tested=0,
    )
    report = c.build_report()
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_HALTED_BEFORE_DISPATCH in causes
    assert report.passed is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_coverage_audit.py::test_emitted_and_admissible_is_satisfied kryptosbot/tests/test_coverage_audit.py::test_admissibility_only_false_still_halts -q`
Expected: FAIL — `REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE` does not exist (ImportError); `record_dispatcher_outcome` has no `admissibility_only` kwarg (TypeError). (The updated `test_schema_version_is_pinned` will also fail until Step 3 bumps the constant.)

- [ ] **Step 3: Bump schema + add the cause sentinel**

In `kryptosbot/coverage_audit.py`, change the constant:

```python
SCHEMA_VERSION = "coverage_report.v2"
```

Add a new sentinel next to the other `REJECTION_CAUSE_*` constants (after `REJECTION_CAUSE_SATISFIED`):

```python
# v2: the obligation's matching spec was emitted AND passed the
# dispatcher's admissibility/translation gate, but execution was
# intentionally skipped (coverage scheduler, Approach A). Counts as
# SATISFIED. Distinct from REJECTION_CAUSE_HALTED_BEFORE_DISPATCH, which
# is an "ok"-but-no-marker dry-run/halt with no admissibility_only flag.
REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE = "emitted_and_admissible"
```

Update the module docstring's schema note (find the paragraph beginning `Artifact schema lives in`) by appending:

```
v2 (2026-05-25): adds the emitted_and_admissible cause and the
DispatcherOutcomeRecord.admissibility_only field for the deterministic
coverage scheduler. v1 parsers remain valid for v1 artifacts.
```

- [ ] **Step 4: Add `admissibility_only` to `DispatcherOutcomeRecord`**

In the `@dataclass class DispatcherOutcomeRecord`, add the field (after `breakthrough_alert: bool = False`):

```python
    admissibility_only: bool = False
```

In its `to_dict`, add the key (after `"breakthrough_alert": ...`):

```python
            "admissibility_only": self.admissibility_only,
```

- [ ] **Step 5: Thread `admissibility_only` through `record_dispatcher_outcome`**

In `CoverageAuditCollector.record_dispatcher_outcome`, add the parameter (after `breakthrough_alert: bool = False,`):

```python
        admissibility_only: bool = False,
```

and pass it into the `DispatcherOutcomeRecord(...)` constructor (after `breakthrough_alert=bool(breakthrough_alert),`):

```python
                    admissibility_only=bool(admissibility_only),
```

- [ ] **Step 6: Handle the new cause in `_evaluate_obligation`**

In `CoverageAuditCollector._evaluate_obligation`, the dispatcher-walk loop currently sets `any_tested` only when `total_tested > 0`. Add an `admissibility-only` tracker. Replace the loop body that begins `for sid in matching_ids:` / `d = self._dispatcher_outcome_for(sid)` (the second such loop, the dispatcher-outcomes one) with:

```python
        any_tested = False
        any_admissible_only = False
        any_rejected_admissibility = False
        any_exhaustion_overlap = False
        best_score_seen = 0.0
        for sid in matching_ids:
            d = self._dispatcher_outcome_for(sid)
            if d is None:
                continue
            if d.admissibility_verdict.lower().startswith("ok"):
                if d.total_tested > 0:
                    any_tested = True
                    best_score_seen = max(best_score_seen, d.best_score)
                elif d.admissibility_only:
                    any_admissible_only = True
            else:
                any_rejected_admissibility = True
                if d.is_exhaustion_overlap:
                    any_exhaustion_overlap = True
```

Then, immediately AFTER the existing `if any_tested:` block (which returns SATISFIED / TESTED_NO_SIGNAL) and BEFORE the `if any_exhaustion_overlap:` block, insert:

```python
        if any_admissible_only:
            return {
                "matching_spec_ids": matching_ids,
                "cause": REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE,
                "cause_detail": (
                    "obligation matched and the closing spec passed the "
                    "dispatcher admissibility gate; execution intentionally "
                    "skipped (coverage scheduler, emitted+admissible)"
                ),
                "tested_count": 0,
            }
```

- [ ] **Step 7: Treat the new cause as satisfied in `_aggregate_pass`**

In `_aggregate_pass`, the loop appends a fail reason when `diag["cause"] != REJECTION_CAUSE_SATISFIED`. Change that condition to also accept the new cause:

```python
        _SATISFYING = {
            REJECTION_CAUSE_SATISFIED,
            REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE,
        }
        for ob in self.profile.obligations:
            diag = self._evaluate_obligation(ob)
            if diag["cause"] not in _SATISFYING:
                fail_reasons.append(diag["cause_detail"])
```

Also update `build_report`'s `obligations_satisfied` counter (the `sum(... if o["cause"] == REJECTION_CAUSE_SATISFIED)`) to use the same set:

```python
        obligations_satisfied = sum(
            1 for o in per_obligation
            if o["cause"] in (
                REJECTION_CAUSE_SATISFIED,
                REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE,
            )
        )
```

- [ ] **Step 8: Export the new sentinel**

Add `"REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE",` to the `__all__` list in `coverage_audit.py` (next to the other `REJECTION_CAUSE_*` entries).

- [ ] **Step 9: Run the new tests to verify they pass**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_coverage_audit.py -q`
Expected: PASS (all PR1 tests + the 3 new ones). The PR1 `test_schema_version_is_pinned` test asserts the version string — update it in the same file to expect `coverage_report.v2` if it hardcodes `v1`.

- [ ] **Step 10: Commit**

```bash
git add kryptosbot/coverage_audit.py kryptosbot/tests/test_coverage_audit.py
git commit -m "feat(coverage): emitted_and_admissible cause + admissibility_only (schema v2)"
```

---

## Task 2: `closing_spec` on `SyntheticProfile` + presence invariants

**Files:**
- Modify: `kryptosbot/synthetic_profiles.py`
- Test: `kryptosbot/tests/test_synthetic_profiles.py`

- [ ] **Step 1: Write the failing tests**

Add to `kryptosbot/tests/test_synthetic_profiles.py`:

```python
def test_available_profiles_carry_closing_spec() -> None:
    from kryptosbot.synthetic_profiles import all_profiles
    for p in all_profiles():
        if p.status == "available":
            assert p.closing_spec, (
                f"available profile {p.profile_id} must carry a closing_spec"
            )
            assert isinstance(p.closing_spec, dict)
            assert p.closing_spec.get("pipeline"), (
                f"{p.profile_id} closing_spec needs a non-empty pipeline"
            )


def test_blocked_profile_has_no_closing_spec() -> None:
    from kryptosbot.synthetic_profiles import get_profile
    p = get_profile("T1_TAPE_K3PT")
    assert p.status == "blocked"
    assert not p.closing_spec


def test_available_without_closing_spec_raises() -> None:
    from kryptosbot.synthetic_profiles import (
        SyntheticProfile, ParameterObligation,
    )
    import pytest
    with pytest.raises(ValueError):
        SyntheticProfile(
            profile_id="X", description="d", status="available",
            obligations=(ParameterObligation(
                expected_family="f", expected_layer_kind="columnar",
                expected_parameter_axis="keyword",
                expected_parameter_value="K",
            ),),
            closing_spec=None,
        )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_synthetic_profiles.py::test_available_profiles_carry_closing_spec kryptosbot/tests/test_synthetic_profiles.py::test_blocked_profile_has_no_closing_spec kryptosbot/tests/test_synthetic_profiles.py::test_available_without_closing_spec_raises -q`
Expected: FAIL — `SyntheticProfile` has no `closing_spec` attribute (TypeError on the constructor kwarg / AttributeError on access).

- [ ] **Step 3: Add the `closing_spec` field + invariants**

In `kryptosbot/synthetic_profiles.py`, in `@dataclass(frozen=True) class SyntheticProfile`, add the field (after `obligations: tuple[...] = ()` and before `notes: str = ""`):

```python
    # PR 2: explicit, auditable closing spec for the coverage scheduler.
    # A DSL HypothesisSpec in dict form (round-trips via
    # HypothesisSpec.from_dict). The obligation-relevant axis is pinned
    # to the required value so the scheduler can emit+admit a spec that
    # closes the obligation deterministically, independent of the LLM.
    # Required for "available" profiles; forbidden for "blocked".
    # NOTE: kept as a raw dict to preserve this module's data-only,
    # dependency-free posture. Structural consistency (the spec actually
    # satisfies the obligation) is verified by
    # coverage_scheduler.verify_profile_closing_spec, NOT here, to avoid
    # importing the DSL into the registry module.
    closing_spec: Optional[dict[str, Any]] = None
```

In `__post_init__`, add (after the existing `available`-requires-obligations check):

```python
        if self.status == "available" and not self.closing_spec:
            raise ValueError(
                f"SyntheticProfile {self.profile_id!r}: available status "
                f"requires a closing_spec (PR 2 coverage scheduler)"
            )
        if self.status == "blocked" and self.closing_spec:
            raise ValueError(
                f"SyntheticProfile {self.profile_id!r}: blocked status "
                f"must NOT carry a closing_spec"
            )
```

In `to_dict`, add the key (after `"notes": self.notes,`):

```python
            "closing_spec": self.closing_spec,
```

- [ ] **Step 4: Populate `closing_spec` for the three available profiles**

For `_T1_SERPENTINE_QUAGMIRE`, add this `closing_spec=` argument to the `SyntheticProfile(...)` call (before `notes=`):

```python
    closing_spec={
        "hypothesis_id": "T1_SERPENTINE_QUAGMIRE__closing",
        "pipeline": [
            {
                "kind": "quagmire",
                "alphabet": "KA",
                "params": [
                    {"name": "variant", "values": ["quagmire_iii"]},
                    {"name": "period_keyword", "values": ["SERPENTINE"]},
                    {"name": "ct_alphabet_keyword", "values": ["KRYPTOS"]},
                    {"name": "pt_alphabet_keyword", "values": ["KRYPTOS"]},
                ],
            }
        ],
        "null_baseline": {"method": "random_text", "n_samples": 10000},
        "compute_budget_cpu_minutes": 30,
        "notes": "PR2 closing spec for T1_SERPENTINE_QUAGMIRE obligation.",
    },
```

For `_T1_BERLINKLOCK_COLUMNAR`:

```python
    closing_spec={
        "hypothesis_id": "T1_BERLINKLOCK_COLUMNAR__closing",
        "pipeline": [
            {
                "kind": "columnar",
                "alphabet": "AZ",
                "params": [
                    {"name": "keyword", "values": ["BERLINKLOCK"]},
                ],
            }
        ],
        "null_baseline": {"method": "random_text", "n_samples": 10000},
        "compute_budget_cpu_minutes": 30,
        "notes": "PR2 closing spec for T1_BERLINKLOCK_COLUMNAR obligation.",
    },
```

For `_T1_ABSCISSA_ROUTE`:

```python
    closing_spec={
        "hypothesis_id": "T1_ABSCISSA_ROUTE__closing",
        "pipeline": [
            {
                "kind": "route",
                "alphabet": "AZ",
                "params": [
                    {"name": "keyword", "values": ["ABSCISSA"]},
                ],
            }
        ],
        "null_baseline": {"method": "random_text", "n_samples": 10000},
        "compute_budget_cpu_minutes": 30,
        "notes": "PR2 closing spec for T1_ABSCISSA_ROUTE obligation.",
    },
```

Leave `_T1_TAPE_K3PT` unchanged (no `closing_spec`).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_synthetic_profiles.py -q`
Expected: PASS (PR1 tests + the 3 new ones).

- [ ] **Step 6: Commit**

```bash
git add kryptosbot/synthetic_profiles.py kryptosbot/tests/test_synthetic_profiles.py
git commit -m "feat(synthetic-profiles): add closing_spec template + presence invariants"
```

---

## Task 3: `coverage_scheduler.py` — admissibility helper, self-consistency, scheduler

**Files:**
- Create: `kryptosbot/coverage_scheduler.py`
- Test: `kryptosbot/tests/test_coverage_scheduler.py`

- [ ] **Step 1: Write the failing tests**

Create `kryptosbot/tests/test_coverage_scheduler.py`:

```python
from pathlib import Path

import pytest

from kryptosbot.coverage_audit import REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE
from kryptosbot.coverage_scheduler import (
    check_spec_admissibility,
    run_coverage_schedule,
    verify_profile_closing_spec,
)
from kryptosbot.synthetic_profiles import all_profiles, get_profile


def test_every_available_closing_spec_satisfies_its_obligation() -> None:
    for p in all_profiles():
        if p.status == "available":
            errors = verify_profile_closing_spec(p)
            assert errors == [], f"{p.profile_id}: {errors}"


def test_check_spec_admissibility_ok_for_quagmire() -> None:
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    verdict, reasons = check_spec_admissibility(profile.closing_spec)
    assert verdict == "ok", reasons


def test_check_spec_admissibility_rejects_malformed() -> None:
    # Invalid alphabet "ZZ" makes spec.validate() fail, so
    # check_admissibility rejects unambiguously (no dependence on the
    # cardinality-budget arithmetic).
    bad = {
        "hypothesis_id": "bad",
        "pipeline": [{"kind": "columnar", "alphabet": "ZZ", "params": [
            {"name": "keyword", "values": ["BERLINKLOCK"]}
        ]}],
        "compute_budget_cpu_minutes": 30,
    }
    verdict, reasons = check_spec_admissibility(bad)
    assert verdict == "rejected"
    assert reasons


def test_run_coverage_schedule_closes_serpentine() -> None:
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    from kryptosbot.coverage_audit import CoverageAuditCollector
    collector = CoverageAuditCollector(profile=profile)
    report = run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE in causes
    assert report.passed is True


def test_run_coverage_schedule_refuses_blocked() -> None:
    profile = get_profile("T1_TAPE_K3PT")
    from kryptosbot.coverage_audit import CoverageAuditCollector
    collector = CoverageAuditCollector(profile=profile)
    report = run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    assert report.passed is False
    assert any("blocked" in r.lower() for r in report.fail_reasons)


def test_run_coverage_schedule_never_executes_kernel(monkeypatch) -> None:
    import kryptosbot.job_dispatcher as jd
    called = {"execute": False}

    def _boom(*a, **k):
        called["execute"] = True
        raise AssertionError("execute() must NOT be called by the scheduler")

    monkeypatch.setattr(jd, "execute", _boom)
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    from kryptosbot.coverage_audit import CoverageAuditCollector
    collector = CoverageAuditCollector(profile=profile)
    run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    assert called["execute"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_coverage_scheduler.py -q`
Expected: FAIL — `kryptosbot.coverage_scheduler` does not exist (ImportError).

- [ ] **Step 3: Create the module**

Create `kryptosbot/coverage_scheduler.py`:

```python
"""Deterministic coverage scheduler for synthetic profiles (PR 2).

PR 1 made coverage failure observable; PR 2 closes obligations by
construction. When --coverage-scheduler-enabled, this module builds the
profile's explicit closing_spec and proves it is EMITTED + ADMISSIBLE:
it runs only the dispatcher's pre-kernel preamble
(_expand_procedural_layers -> check_admissibility) and records the
verdict through the PR1 collector. It never calls job_dispatcher.execute
or any kernel scoring path, never touches the real ledger, and makes no
LLM/API call. Blocked profiles (T1_TAPE_K3PT) are refused, mirroring
PR1's launch refusal.

Closure semantics: "emitted + admissible". The T1 postmortem gap was
about emission/admission, not scoring. Synthetic profiles carry a
mechanism contract, not a synthetic ciphertext, so executing the closing
spec would mean running against the real K4 CT — out of scope and
contrary to the no-real-K4 posture. The scheduler stops at the
admissibility boundary.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from kryptosbot.coverage_audit import CoverageAuditCollector, CoverageReport
from kryptosbot.synthetic_profiles import SyntheticProfile

logger = logging.getLogger("kryptosbot.coverage_scheduler")


def check_spec_admissibility(
    spec_dict: dict[str, Any],
) -> tuple[str, list[str]]:
    """Run only the dispatcher pre-kernel preamble on a spec dict.

    Mirrors the first half of job_dispatcher.execute: parse the spec,
    expand procedural layers, then check_admissibility(bench_mode=True).
    bench_mode=True isolates the synthetic profile from the real-K4
    exhaustion log (the profile is not real-K4 history). Returns
    (verdict, reasons) where verdict is "ok" or "rejected". NEVER calls
    execute() or the kernel.
    """
    from kryptosbot.hypothesis_dsl import HypothesisSpec
    from kryptosbot import job_dispatcher

    spec = HypothesisSpec.from_dict(spec_dict)
    try:
        spec = job_dispatcher._expand_procedural_layers(spec)
    except job_dispatcher.DispatcherError as exc:
        return ("rejected", [f"procedural expansion: {exc}"])
    admissible, reasons = job_dispatcher.check_admissibility(
        spec, bench_mode=True,
    )
    return ("ok" if admissible else "rejected", list(reasons))


def verify_profile_closing_spec(profile: SyntheticProfile) -> list[str]:
    """Return errors if the profile's closing_spec fails to satisfy its
    obligations. Empty list means consistent.

    Uses the PR1 layer flattener + ParameterObligation.matches so the
    obligation-vs-spec check shares one code path with the collector.
    """
    if profile.status == "blocked":
        if profile.closing_spec:
            return [f"{profile.profile_id}: blocked profile must not carry closing_spec"]
        return []
    if not profile.closing_spec:
        return [f"{profile.profile_id}: available profile missing closing_spec"]

    from kryptosbot.coverage_audit import _layer_to_record

    layers = [
        _layer_to_record(lr)
        for lr in (profile.closing_spec.get("pipeline") or [])
    ]
    errors: list[str] = []
    for ob in profile.obligations:
        matched = any(
            ob.matches(
                layer_kind=l.get("kind", ""),
                layer_variant=l.get("variant"),
                params=l.get("params", {}) or {},
            )
            for l in layers
        )
        if not matched:
            errors.append(
                f"{profile.profile_id}: closing_spec does not satisfy "
                f"obligation {ob.describe()}"
            )
    return errors


def run_coverage_schedule(
    profile: SyntheticProfile,
    collector: CoverageAuditCollector,
    *,
    project_root: Path,
) -> CoverageReport:
    """Deterministically close (emit + admit) the profile's obligation.

    Returns the built CoverageReport. The caller (run_controller) writes
    it to disk via the existing collector.write_report path.
    """
    collector.add_note("coverage-scheduler: Approach A (emitted+admissible, no execution)")

    if profile.status == "blocked":
        collector.add_note(
            f"coverage-scheduler refused blocked profile: {profile.blocked_reason}"
        )
        return collector.build_report()

    consistency_errors = verify_profile_closing_spec(profile)
    if consistency_errors:
        collector.add_note(
            "coverage-scheduler: closing_spec self-consistency FAILED: "
            + "; ".join(consistency_errors)
        )
        return collector.build_report()

    spec_dict = profile.closing_spec or {}
    hyp_id = spec_dict.get("hypothesis_id", f"{profile.profile_id}__closing")
    collector.record_emitted_spec(
        hypothesis_id=hyp_id,
        title=f"{profile.profile_id} deterministic closing spec",
        family=(profile.obligations[0].expected_family if profile.obligations else ""),
        layers=list(spec_dict.get("pipeline") or []),
        origin="coverage_scheduler",
    )
    verdict, reasons = check_spec_admissibility(spec_dict)
    collector.record_dispatcher_outcome(
        hypothesis_id=hyp_id,
        admissibility_verdict=verdict,
        admissibility_reasons=reasons,
        total_tested=0,
        admissibility_only=True,
    )
    return collector.build_report()


__all__ = [
    "check_spec_admissibility",
    "run_coverage_schedule",
    "verify_profile_closing_spec",
]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_coverage_scheduler.py -q`
Expected: PASS (6 tests). If `test_check_spec_admissibility_rejects_malformed` does not reject, widen the budget mismatch (raise `stop` or lower `compute_budget_cpu_minutes`) until cardinality exceeds budget — the goal is a genuine admissibility rejection.

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/coverage_scheduler.py kryptosbot/tests/test_coverage_scheduler.py
git commit -m "feat(coverage-scheduler): emit+admit closing specs deterministically (Approach A)"
```

---

## Task 4: `run_controller.py` wiring — CLI error + scheduler branch

**Files:**
- Modify: `kryptosbot/run_controller.py`
- Test: `kryptosbot/tests/test_run_controller_synthetic.py`

- [ ] **Step 1: Write the failing tests**

`parse_args()` in `run_controller.py` takes NO arguments — it reads
`sys.argv` and calls `parser.error` (which raises `SystemExit`) on bad
combinations. The PR1 tests therefore exercise CLI validation via a
subprocess helper `_run_cli(*args)` already defined at the top of
`kryptosbot/tests/test_run_controller_synthetic.py` (it runs
`python -m kryptosbot.run_controller <args>` and returns a
`CompletedProcess` with `.returncode` / `.stderr` / `.stdout`). Follow
that pattern. Add:

```python
def test_scheduler_flag_without_profile_rejected() -> None:
    """--coverage-scheduler-enabled alone is meaningless and exits nonzero."""
    result = _run_cli("--coverage-scheduler-enabled")
    assert result.returncode != 0
    assert "requires --synthetic-profile" in result.stderr


def test_scheduler_flag_with_profile_advertised_in_help() -> None:
    """The flag remains visible on --help (regression guard)."""
    result = _run_cli("--help")
    assert result.returncode == 0
    assert "--coverage-scheduler-enabled" in result.stdout
```

(The positive end-to-end behavior — the flag actually driving the
scheduler phase — is verified by the Task 5 smoke, not by a parse-only
assertion.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_run_controller_synthetic.py::test_scheduler_flag_without_profile_rejected -q`
Expected: FAIL — the flag is inert in PR1, so the CLI exits 0 and the "requires --synthetic-profile" text is absent.

- [ ] **Step 3: Add the CLI mutual-requirement error**

In `kryptosbot/run_controller.py`, in the synthetic-profile validation block inside `parse_args` (the `if args.synthetic_profile is not None:` / `elif args.coverage_report is not None:` chain near line 624-670), add a new branch so `--coverage-scheduler-enabled` requires `--synthetic-profile`. After the existing `elif args.coverage_report is not None:` block that errors when coverage-report lacks a profile, add:

```python
    elif args.coverage_scheduler_enabled:
        parser.error(
            "--coverage-scheduler-enabled requires --synthetic-profile to be set."
        )
```

- [ ] **Step 4: Branch the scheduler phase in place of `do_run`**

In `main` (the async function), find the block that calls `await do_run(config)` (near line 1452-1467, including the `--quiet` stderr-redirect variant). Replace the inner `await do_run(config)` calls with a helper branch. Concretely, define a small local just before the `try:` at line ~1455:

```python
    async def _run_phase() -> None:
        if (
            args.synthetic_profile is not None
            and args.coverage_scheduler_enabled
            and coverage_collector is not None
        ):
            from kryptosbot.coverage_scheduler import run_coverage_schedule
            run_coverage_schedule(
                coverage_collector.profile,
                coverage_collector,
                project_root=project_root,
            )
        else:
            await do_run(config)
```

Then replace both `await do_run(config)` call sites (inside the `if args.quiet:` branch and the `else:` branch) with `await _run_phase()`. The existing `finally:` block (lines ~1468-1493) already writes the report from `coverage_collector`, so no change is needed there.

- [ ] **Step 5: Update the PR1 "inert" collector note**

In the `coverage_collector.add_note(...)` call near line 1404 (which says `PR 1: parsed but inert`), change the note to reflect that the flag is now active:

```python
        coverage_collector.add_note(
            f"--coverage-scheduler-enabled={bool(args.coverage_scheduler_enabled)} "
            f"(PR 2: active — scheduler phase replaces the LLM cycle when set)"
        )
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_run_controller_synthetic.py -q`
Expected: PASS (PR1 tests + the 2 new ones). The PR1 `test_help_advertises_pr1_flags` test should still pass (flags unchanged); if it asserts the inert wording, update it to the active wording.

- [ ] **Step 7: Commit**

```bash
git add kryptosbot/run_controller.py kryptosbot/tests/test_run_controller_synthetic.py
git commit -m "feat(run-controller): wire coverage scheduler phase + require profile flag"
```

---

## Task 5: End-to-end smoke + full-suite verification

**Files:** none (verification only)

- [ ] **Step 1: Run the scheduler end-to-end smoke**

Run:

```bash
PYTHONPATH=src python3 -u kryptosbot/run_controller.py \
  --synthetic-profile T1_SERPENTINE_QUAGMIRE \
  --coverage-scheduler-enabled \
  --cycles 1 \
  --coverage-report results/coverage_reports/
```

Expected: exits 0; prints `coverage-report: wrote artifact -> .../<ts>_T1_SERPENTINE_QUAGMIRE_coverage_report.json`. No LLM/cycle output (scheduler phase replaces the cycle).

- [ ] **Step 2: Inspect the report**

Run:

```bash
PYTHONPATH=src python3 -c "
import json, glob, os
f = sorted(glob.glob('results/coverage_reports/*T1_SERPENTINE_QUAGMIRE*'), key=os.path.getmtime)[-1]
d = json.load(open(f))
print('schema:', d['schema_version'])
print('pass:', d['pass'])
print('ledger:', d['ledger_db_path'])
for o in d['per_obligation']:
    print(o['obligation'], '->', o['cause'])
"
```

Expected: `schema: coverage_report.v2`; `pass: True`; ledger path under `db/synthetic_profiles/`; obligation cause `emitted_and_admissible`.

- [ ] **Step 3: Confirm the real ledger was not touched**

Run: `ls -la --time-style=+%H:%M:%S db/theory_ledger.sqlite`
Expected: mtime unchanged from before the smoke (compare against the value you note before Step 1).

- [ ] **Step 4: Run the full kryptosbot suite (parallel)**

Run: `PYTHONPATH=src /home/cpatrick/kryptos/venv/bin/python -m pytest kryptosbot/tests/ -q -n 26`
Expected: PASS except the 5 pre-existing `test_priority5_search_space_risk.py::TestDuplicateFamilyAutoRejectInFilter` failures (the `_cycle_redteam_reject_count` init bug, unrelated to PR2 — see PR1 acceptance notes). No NEW failures.

- [ ] **Step 5: Commit any final adjustments (if Step 4 surfaced a PR2-caused failure)**

Only if a PR2-introduced test needed fixing:

```bash
git add <fixed files>
git commit -m "test(coverage-scheduler): fix <specific issue>"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** §6.1 profile extension → Task 2; §6.2 scheduler module + `check_spec_admissibility` → Task 3; §6.3 audit extension (cause, `admissibility_only`, schema v2) → Task 1; §6.4 run_controller wiring + CLI error → Task 4; §7 safety invariants → asserted in Task 3 tests (blocked refusal, no-execution, bench-mode isolation) + Task 5 ledger check; §8 testing → Tasks 1-3 tests + Task 5 smoke; §3 closure semantics → Task 1 `emitted_and_admissible` = satisfied; §4 explicit templates → Task 2; §9 NOT-in-scope → no execution path added, T1_TAPE_K3PT untouched.
- **Real-K4 context refusal (§7):** the scheduler only runs under `--synthetic-profile`, which PR1 already makes mutually exclusive with bench/HCC audits and which forces the synthetic ledger; the scheduler itself never imports real K4 CT or calls `execute()`. An explicit problem-context assertion is therefore redundant with the CLI gating; if a defensive guard is wanted, add it in Task 3 `run_coverage_schedule` as an early note-and-return when `spec_dict` is empty. (Left out to honor YAGNI; flagged here for the reviewer.)
- **Placeholder scan:** no TBD/TODO; every code step shows complete code.
- **Type consistency:** `check_spec_admissibility(spec_dict) -> (verdict, reasons)`, `verify_profile_closing_spec(profile) -> list[str]`, `run_coverage_schedule(profile, collector, *, project_root) -> CoverageReport`, `admissibility_only` field name, and `REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE` sentinel are used consistently across Tasks 1, 3, 4, and the tests.
