# PR4 Route Profile Redefinition — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redefine the route synthetic profile from the non-executable `T1_ABSCISSA_ROUTE` (keyword=ABSCISSA, no route mechanism) into `T1_SERPENTINE_ROUTE` — a genuine serpentine route transposition that is dispatch-executable and a PR3-style recovery target reaching `satisfied`.

**Architecture:** Pure profile + test edits. No generator/scheduler/run_controller change — the redefined profile is single-layer + `recovery_target=True`, so it flows through PR3's existing recovery path. Because all three available profiles then become recovery targets, the scheduler's `emitted_and_admissible` branch loses its real-profile user and is kept tested via an inline non-recovery fixture.

**Tech Stack:** Python 3.12, stdlib core; `pytest` via `venv/bin/python -m pytest -n <N>` for parallel runs.

**Spec:** `docs/specs/2026-05-26-route-profile-redefinition-pr4-design.md`

**Verified facts (run live, 2026-05-26):**
- The serpentine route closing_spec (`variant=serpentine`, `rows=10`, `cols=10`) generates a 97-char CT (`!= PT`, 24 cribs) and round-trips via `execute_from_json(..., bench_mode=True, parallel=False)` to `verdict ok, total_tested 1, best_score 24.0`.
- The obligation `(kind=route, axis=variant, value=serpentine, layer_variant=None)` matches the flattened closing_spec layer (`_layer_to_record` exposes `params["variant"]==["serpentine"]`).
- Current registry sorted IDs: `[T1_ABSCISSA_ROUTE, T1_BERLINCLOCK_COLUMNAR, T1_SERPENTINE_QUAGMIRE, T1_TAPE_K3PT]`. After rename: `[T1_BERLINCLOCK_COLUMNAR, T1_SERPENTINE_QUAGMIRE, T1_SERPENTINE_ROUTE, T1_TAPE_K3PT]`.

---

## File Structure

- **Modify** `kryptosbot/synthetic_profiles.py` — redefine `_T1_ABSCISSA_ROUTE` → `_T1_SERPENTINE_ROUTE` (id, obligation, closing_spec, recovery_target, notes) + registry key. (Task 1)
- **Modify** `kryptosbot/tests/test_synthetic_profiles.py` — registry-ID list, recovery-target set, route obligation shape. (Task 1)
- **Modify** `kryptosbot/tests/test_coverage_synthetic.py` — add serpentine route to the round-trip loop. (Task 2)
- **Modify** `kryptosbot/tests/test_coverage_scheduler.py` — add route to the `satisfied` loop; replace `test_route_stays_emitted_and_admissible` and repoint `test_run_coverage_schedule_never_executes_kernel` to an inline non-recovery fixture. (Task 2)
- **Verify** full suite. (Task 3)

Parallel runs: `PYTHONPATH=src /home/cpatrick/kryptos/venv/bin/python -m pytest <targets> -q -n 8`.

---

## Task 1: Redefine the profile + update profile-registry tests

**Files:**
- Modify: `kryptosbot/synthetic_profiles.py`
- Test: `kryptosbot/tests/test_synthetic_profiles.py`

- [ ] **Step 1: Update the failing tests first**

In `kryptosbot/tests/test_synthetic_profiles.py`:

(a) `test_registry_exposes_pr1_profile_ids` — change the expected list to the new sorted order:
```python
    assert ids == [
        "T1_BERLINCLOCK_COLUMNAR",
        "T1_SERPENTINE_QUAGMIRE",
        "T1_SERPENTINE_ROUTE",
        "T1_TAPE_K3PT",
    ]
```

(b) Rename/repoint the recovery-target set test to three targets:
```python
def test_recovery_targets_are_the_three_executable_profiles() -> None:
    from kryptosbot.synthetic_profiles import all_profiles
    targets = {p.profile_id for p in all_profiles() if p.recovery_target}
    assert targets == {
        "T1_SERPENTINE_QUAGMIRE",
        "T1_BERLINCLOCK_COLUMNAR",
        "T1_SERPENTINE_ROUTE",
    }
```
If the prior `test_recovery_targets_are_quagmire_and_columnar` exists, replace it with the above (do not leave the stale two-target assertion).

(c) Add a route-obligation shape test:
```python
def test_serpentine_route_obligation_shape() -> None:
    from kryptosbot.synthetic_profiles import get_profile
    p = get_profile("T1_SERPENTINE_ROUTE")
    assert p.status == "available"
    assert p.recovery_target is True
    ob = p.obligations[0]
    assert ob.expected_layer_kind == "route"
    assert ob.expected_parameter_axis == "variant"
    assert ob.expected_parameter_value == "serpentine"
    layer = p.closing_spec["pipeline"][0]
    names = {pr["name"]: pr for pr in layer["params"]}
    assert names["variant"]["values"] == ["serpentine"]
    assert names["rows"]["values"] == [10]
    assert names["cols"]["values"] == [10]
```

(d) Grep the test file for any remaining `ABSCISSA` or `T1_ABSCISSA_ROUTE` references and update/remove them (e.g. a test that referenced the old route keyword). Use:
`grep -n "ABSCISSA\|T1_ABSCISSA_ROUTE" kryptosbot/tests/test_synthetic_profiles.py`

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_synthetic_profiles.py -q`
Expected: FAIL — `T1_SERPENTINE_ROUTE` not in registry yet; `get_profile("T1_SERPENTINE_ROUTE")` raises KeyError; recovery-target set still `{quagmire, columnar}`.

- [ ] **Step 3: Redefine the profile in `kryptosbot/synthetic_profiles.py`**

Find the `_T1_ABSCISSA_ROUTE = SyntheticProfile(...)` definition and its leading comment block. Replace the entire definition (comment + assignment) with:

```python
# T1_SERPENTINE_ROUTE
#
# Synthetic serpentine (boustrophedon) route transposition over a 10x10
# grid. The dispatcher's route translator cites Sanborn's AAA-archive
# description of Kryptos as "a serpentine copper screen ... with Blaise
# De Vigenère's Tableaux" as the natural serpentine anchor, so this is the
# thematically-consistent route coverage profile. A recovery target (PR3):
# the closing_spec is dispatch-executable (variant + rows/cols) and
# round-trips a synthetic CT to crib_score 24.
#
# (Replaces the former T1_ABSCISSA_ROUTE, whose keyword=ABSCISSA obligation
# had no executable mapping in the dispatcher's keyword-less route model.)
_T1_SERPENTINE_ROUTE = SyntheticProfile(
    profile_id="T1_SERPENTINE_ROUTE",
    description=(
        "Synthetic serpentine route transposition (boustrophedon read over "
        "a 10x10 grid). Passes when at least one dispatched HypothesisSpec "
        "includes a route layer whose variant parameter materializes to "
        "serpentine; as a recovery target it must recover the synthetic "
        "plaintext (crib_score >= SIGNAL)."
    ),
    status="available",
    blocked_reason="",
    required_kinds=("route",),
    obligations=(
        ParameterObligation(
            expected_family="transposition_route",
            expected_layer_kind="route",
            expected_layer_variant=None,
            expected_parameter_axis="variant",
            expected_parameter_value="serpentine",
            minimum_expected_dispatch=1,
        ),
    ),
    closing_spec={
        "hypothesis_id": "T1_SERPENTINE_ROUTE__closing",
        "pipeline": [
            {
                "kind": "route",
                "alphabet": "AZ",
                "params": [
                    {"name": "variant", "values": ["serpentine"]},
                    # 10x10 = 100 >= 97 so the grid covers every CT position.
                    {"name": "rows", "values": [10]},
                    {"name": "cols", "values": [10]},
                ],
            }
        ],
        "null_baseline": {"method": "random_text", "n_samples": 10000},
        "compute_budget_cpu_minutes": 30,
        "notes": "PR4 closing spec for T1_SERPENTINE_ROUTE obligation.",
    },
    recovery_target=True,
    notes=(
        "Serpentine route coverage. variant=serpentine pins the obligation; "
        "rows/cols make the spec executable and round-trippable for PR3 "
        "real-recovery dispatch. The Kryptos serpentine-screen anchor "
        "motivates the variant choice."
    ),
)
```

Then update the `_REGISTRY` dict entry: replace
```python
    _T1_ABSCISSA_ROUTE.profile_id: _T1_ABSCISSA_ROUTE,
```
with
```python
    _T1_SERPENTINE_ROUTE.profile_id: _T1_SERPENTINE_ROUTE,
```

Grep the source for any remaining stale references:
`grep -n "ABSCISSA\|_T1_ABSCISSA_ROUTE\|T1_ABSCISSA_ROUTE" kryptosbot/synthetic_profiles.py`
Expected: none. Fix any that remain.

- [ ] **Step 4: Run the profile-registry tests**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_synthetic_profiles.py -q`
Expected: ALL pass.

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/synthetic_profiles.py kryptosbot/tests/test_synthetic_profiles.py
git commit -m "feat(synthetic-profiles): redefine route profile as executable serpentine recovery target"
```

---

## Task 2: Update generator + scheduler tests (route recovers; non-recovery branch via fixture)

**Files:**
- Test: `kryptosbot/tests/test_coverage_synthetic.py`
- Test: `kryptosbot/tests/test_coverage_scheduler.py`

- [ ] **Step 1: Add the route to the generator round-trip loop**

In `kryptosbot/tests/test_coverage_synthetic.py`, the round-trip test currently loops over `("T1_SERPENTINE_QUAGMIRE", "T1_BERLINCLOCK_COLUMNAR")`. Add the route:
```python
    for pid in (
        "T1_SERPENTINE_QUAGMIRE",
        "T1_BERLINCLOCK_COLUMNAR",
        "T1_SERPENTINE_ROUTE",
    ):
```
Do the same for `test_generated_ct_is_97_chars_and_differs_from_pt` if it also loops over the two recovery targets (add `"T1_SERPENTINE_ROUTE"` to that loop too).

- [ ] **Step 2: Update the scheduler tests**

In `kryptosbot/tests/test_coverage_scheduler.py`:

(a) Add the route to the recovery-target `satisfied` loop in `test_recovery_target_reaches_satisfied_via_scoring`:
```python
    for pid in (
        "T1_SERPENTINE_QUAGMIRE",
        "T1_BERLINCLOCK_COLUMNAR",
        "T1_SERPENTINE_ROUTE",
    ):
```

(b) Add an inline non-recovery fixture helper near the top of the test module (after imports):
```python
def _make_non_recovery_available_profile():
    """A minimal available, NON-recovery-target profile for exercising the
    scheduler's emitted_and_admissible branch (no registry profile is
    non-recovery after PR4)."""
    from kryptosbot.synthetic_profiles import SyntheticProfile, ParameterObligation
    return SyntheticProfile(
        profile_id="X_NONRECOVERY_COLUMNAR",
        description="inline non-recovery fixture",
        status="available",
        obligations=(
            ParameterObligation(
                expected_family="transposition_columnar",
                expected_layer_kind="columnar",
                expected_parameter_axis="keyword",
                expected_parameter_value="BERLINCLOCK",
            ),
        ),
        closing_spec={
            "hypothesis_id": "X_NONRECOVERY_COLUMNAR__closing",
            "pipeline": [{
                "kind": "columnar", "alphabet": "AZ",
                "params": [
                    {"name": "keyword", "values": ["BERLINCLOCK"]},
                    {"name": "width", "values": [11]},
                    {"name": "col_order",
                     "values": [[0, 3, 10, 6, 4, 8, 1, 7, 9, 2, 5]]},
                ],
            }],
            "compute_budget_cpu_minutes": 30,
        },
        recovery_target=False,
    )
```

(c) Replace `test_route_stays_emitted_and_admissible` with a fixture-based test:
```python
def test_non_recovery_profile_reaches_emitted_and_admissible() -> None:
    from kryptosbot.coverage_audit import (
        CoverageAuditCollector, REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE,
    )
    profile = _make_non_recovery_available_profile()
    assert profile.recovery_target is False
    collector = CoverageAuditCollector(profile=profile)
    report = run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE in causes
    assert report.passed is True
```

(d) Repoint `test_run_coverage_schedule_never_executes_kernel` to the fixture (the route profile now executes, so it can no longer be the no-execute subject):
```python
def test_run_coverage_schedule_never_executes_kernel(monkeypatch) -> None:
    # Only recovery_target profiles dispatch the kernel. A non-recovery
    # available profile keeps the PR2 admissibility-only path and must
    # NEVER call execute(). (No registry profile is non-recovery after PR4,
    # so use an inline fixture.)
    import kryptosbot.job_dispatcher as jd
    called = {"execute": False}

    def _boom(*a, **k):
        called["execute"] = True
        raise AssertionError("execute() must NOT be called for a non-recovery profile")

    monkeypatch.setattr(jd, "execute", _boom)
    from kryptosbot.coverage_audit import CoverageAuditCollector
    profile = _make_non_recovery_available_profile()
    assert profile.recovery_target is False
    collector = CoverageAuditCollector(profile=profile)
    run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    assert called["execute"] is False
```

(e) Grep the test file for stale references and fix:
`grep -n "ABSCISSA\|T1_ABSCISSA_ROUTE\|route_stays" kryptosbot/tests/test_coverage_scheduler.py`

- [ ] **Step 3: Run the generator + scheduler + audit tests**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_coverage_synthetic.py kryptosbot/tests/test_coverage_scheduler.py kryptosbot/tests/test_coverage_audit.py -q`
Expected: ALL pass — the three recovery targets (incl. route) reach `satisfied`/best_score 24; the inline fixture covers `emitted_and_admissible` and the no-execute path.

- [ ] **Step 4: Commit**

```bash
git add kryptosbot/tests/test_coverage_synthetic.py kryptosbot/tests/test_coverage_scheduler.py
git commit -m "test(coverage): route recovers; cover emitted_and_admissible via inline non-recovery fixture"
```

---

## Task 3: Smoke + full-suite verification

**Files:** none (verification only)

- [ ] **Step 1: Record real ledger mtime, run the serpentine-route scheduler smoke**

```bash
cd /home/cpatrick/kryptos
ls -la --time-style=+%H:%M:%S db/theory_ledger.sqlite
PYTHONPATH=src python3 -u kryptosbot/run_controller.py \
  --synthetic-profile T1_SERPENTINE_ROUTE \
  --coverage-scheduler-enabled \
  --cycles 1 \
  --coverage-report results/coverage_reports/
```
Expected: exits 0; prints `coverage-report: wrote artifact -> .../<ts>_T1_SERPENTINE_ROUTE_coverage_report.json`.

- [ ] **Step 2: Inspect the report**

```bash
PYTHONPATH=src python3 -c "
import json, glob, os
f = sorted(glob.glob('results/coverage_reports/*T1_SERPENTINE_ROUTE*'), key=os.path.getmtime)[-1]
d = json.load(open(f))
print('schema:', d['schema_version']); print('pass:', d['pass']); print('best_score:', d['best_score'])
print('ledger:', d['ledger_db_path'])
for o in d['per_obligation']:
    print(o['obligation'], '->', o['cause'])
"
```
Expected: `schema coverage_report.v2`, `pass True`, `best_score 24`, ledger under `db/synthetic_profiles/`, obligation cause `satisfied`.

- [ ] **Step 3: Confirm real ledger untouched**

Run: `ls -la --time-style=+%H:%M:%S db/theory_ledger.sqlite`
Expected: mtime unchanged from Step 1.

- [ ] **Step 4: Rebuild null baselines at current HEAD, then run the full suite**

Committing Tasks 1-2 moved HEAD, re-staling the commit-pinned null baselines (known repo characteristic). Rebuild, then run:
```bash
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py >/dev/null 2>&1 && echo "standard rebuilt"
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines_r2_4.py >/dev/null 2>&1 && echo "r2_4 rebuilt"
PYTHONPATH=src /home/cpatrick/kryptos/venv/bin/python -m pytest kryptosbot/tests/ -q -n 26
```
Expected: full suite green (0 failures). Leave `null_baselines/manifest.json` UNCOMMITTED (re-pinned to current HEAD; committing it would re-stale — repo convention).

- [ ] **Step 5: Commit any final adjustment (only if Step 4 surfaced a PR4-caused failure)**

```bash
git add <fixed files>
git commit -m "test(route-redef): fix <specific issue>"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** §4.1 profile redefinition → Task 1 Step 3; §4.2 no generator/scheduler change → respected (Tasks touch only profiles + tests); §4.3 inline non-recovery fixture → Task 2 (b)(c)(d); §5 tests → Tasks 1-2 (registry IDs, recovery-target set, route obligation shape, round-trip, scheduler satisfied, fixture-based emitted_and_admissible + no-execute); §6 safety (no real K4, ledger untouched) → Task 3 smoke; §7 NOT-in-scope (no ABSCISSA revival, serpentine only, TAPE stays blocked) → respected.
- **Placeholder scan:** no TBD/TODO; every code step shows complete code. The grep steps name the exact command and expected outcome.
- **Type/value consistency:** profile_id `T1_SERPENTINE_ROUTE`, obligation `(route, variant, serpentine)`, closing_spec `variant=["serpentine"]/rows=[10]/cols=[10]`, `recovery_target=True`, and the inline fixture's columnar `col_order=[0,3,10,6,4,8,1,7,9,2,5]` (matches the real columnar profile's verified literal) are consistent across Tasks 1-2. The round-trip `best_score==24` and obligation-match were both verified live against these exact values before this plan was written.
