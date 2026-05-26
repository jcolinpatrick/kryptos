# PR3 Synthetic-CT Real-Recovery Coverage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the coverage scheduler so recovery-target profiles (quagmire, columnar) generate a synthetic ciphertext from their own mechanism, dispatch the `closing_spec` against it, and require the kernel scoring path to actually recover the known plaintext (crib_score ≥ SIGNAL) — real recovery, not just admissibility. Never touches the real K4 ciphertext.

**Architecture:** A new `coverage_synthetic.py` generates a synthetic CT by reusing the dispatcher's spec→pipeline translation in encrypt direction (guaranteed round-trip). `coverage_scheduler.run_coverage_schedule` branches on a new `SyntheticProfile.recovery_target` flag: recovery targets generate + dispatch + score (fail-closed); non-targets (route) keep PR2's emitted+admissible path. The columnar `closing_spec` is enriched with executable `width`/`col_order`. No `run_controller` change.

**Tech Stack:** Python 3.12, stdlib core; `pytest` via `venv/bin/python -m pytest -n <N>` for parallel runs. DSL/dispatcher in `kryptosbot/job_dispatcher.py` + `kryptosbot/hypothesis_dsl.py`; kernel transforms in `src/kryptos/kernel/transforms/compose.py`.

**Spec:** `docs/specs/2026-05-26-coverage-recovery-pr3-design.md`

**Verified facts (against live code, 2026-05-26):**
- `JobResult` fields: `total_tested: int`, `best_score: float`, `best_candidate: Optional[dict]`.
- `keyword_to_order("BERLINCLOCK", 11)` == `[0, 3, 10, 6, 4, 8, 1, 7, 9, 2, 5]`.
- `kryptos.kernel.constants.CRIB_POSITIONS` == the 24 positions `[21..33, 63..73]`.
- Dispatcher helpers: `_enumerate_bindings(spec) -> Iterator[tuple[tuple[str,Any],...]]`; `_build_pipeline_config(spec, bindings, *, text_length=None) -> dict` returning `{"name","direction":"decrypt","steps":[{"type","params"}...]}`; `_expand_procedural_layers(spec) -> spec`; `DispatcherError`; `execute(spec, *, challenge_ciphertext=None, challenge_crib_dict=None, bench_mode=False, parallel=None, ...) -> JobResult`.
- `compose.build_pipeline(config)` IGNORES `PipelineConfig.direction` — encrypt direction must be set on EACH step's `params["direction"]="encrypt"`.
- The BERLINCLOCK rename already landed (commit `6a80383`): profile id is `T1_BERLINCLOCK_COLUMNAR`, keyword `BERLINCLOCK`.

---

## File Structure

- **Modify** `kryptosbot/synthetic_profiles.py` — add `recovery_target` field + invariant; set it on quagmire & columnar; enrich columnar `closing_spec` with `width`/`col_order`; add to `to_dict`. (Task 1)
- **Create** `kryptosbot/coverage_synthetic.py` — `CANONICAL_PLAINTEXT`, `generate_synthetic_challenge`. (Task 2)
- **Modify** `kryptosbot/coverage_scheduler.py` — `run_coverage_schedule` recovery-target scoring branch (fail-closed). (Task 3)
- **Create** `kryptosbot/tests/test_coverage_synthetic.py` — generator round-trip + executability. (Task 2)
- **Modify** `kryptosbot/tests/test_synthetic_profiles.py` — `recovery_target` invariant tests. (Task 1)
- **Modify** `kryptosbot/tests/test_coverage_scheduler.py` — scheduler scoring/fail-closed/route tests. (Task 3)

Parallel test runs: `PYTHONPATH=src /home/cpatrick/kryptos/venv/bin/python -m pytest <targets> -q -n 8`. Single-file runs may use `PYTHONPATH=src python3 -m pytest`.

---

## Task 1: `recovery_target` flag + executable columnar closing_spec

**Files:**
- Modify: `kryptosbot/synthetic_profiles.py`
- Test: `kryptosbot/tests/test_synthetic_profiles.py`

- [ ] **Step 1: Write the failing tests**

Add to `kryptosbot/tests/test_synthetic_profiles.py`:

```python
def test_recovery_targets_are_quagmire_and_columnar() -> None:
    from kryptosbot.synthetic_profiles import all_profiles
    targets = {p.profile_id for p in all_profiles() if p.recovery_target}
    assert targets == {"T1_SERPENTINE_QUAGMIRE", "T1_BERLINCLOCK_COLUMNAR"}


def test_recovery_target_implies_available_with_closing_spec() -> None:
    from kryptosbot.synthetic_profiles import all_profiles
    for p in all_profiles():
        if p.recovery_target:
            assert p.status == "available"
            assert p.closing_spec


def test_blocked_profile_cannot_be_recovery_target() -> None:
    from kryptosbot.synthetic_profiles import SyntheticProfile
    import pytest
    with pytest.raises(ValueError):
        SyntheticProfile(
            profile_id="X", description="d", status="blocked",
            blocked_reason="r", recovery_target=True,
        )


def test_columnar_closing_spec_carries_executable_params() -> None:
    from kryptosbot.synthetic_profiles import get_profile
    p = get_profile("T1_BERLINCLOCK_COLUMNAR")
    layer = p.closing_spec["pipeline"][0]
    names = {pr["name"]: pr for pr in layer["params"]}
    assert names["keyword"]["values"] == ["BERLINCLOCK"]
    assert names["width"]["values"] == [11]
    assert names["col_order"]["values"] == [[0, 3, 10, 6, 4, 8, 1, 7, 9, 2, 5]]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_synthetic_profiles.py -k "recovery_target or executable_params" -q`
Expected: FAIL — `SyntheticProfile` has no `recovery_target` attribute (TypeError/AttributeError); columnar closing_spec lacks `width`/`col_order`.

- [ ] **Step 3: Add the `recovery_target` field + invariant**

In `kryptosbot/synthetic_profiles.py`, in `@dataclass(frozen=True) class SyntheticProfile`, add the field after `closing_spec` (before `notes`):

```python
    # PR 3: when True, the coverage scheduler generates a synthetic CT from
    # this profile's mechanism, dispatches the closing_spec against it, and
    # requires real recovery (crib_score >= SIGNAL) — not just admissibility.
    # Fail-closed: a recovery target whose CT generation/dispatch fails is a
    # hard failure, never a silent downgrade to emitted_and_admissible.
    recovery_target: bool = False
```

In `__post_init__`, add (after the existing `closing_spec` invariants):

```python
        if self.recovery_target:
            if self.status != "available":
                raise ValueError(
                    f"SyntheticProfile {self.profile_id!r}: recovery_target "
                    f"requires status=='available'"
                )
            if not self.closing_spec:
                raise ValueError(
                    f"SyntheticProfile {self.profile_id!r}: recovery_target "
                    f"requires a closing_spec"
                )
```

In `to_dict`, add after `"closing_spec": self.closing_spec,`:

```python
            "recovery_target": self.recovery_target,
```

- [ ] **Step 4: Set `recovery_target=True` on quagmire**

In the `_T1_SERPENTINE_QUAGMIRE = SyntheticProfile(...)` call, add the argument (e.g. right after `closing_spec={...},`):

```python
    recovery_target=True,
```

- [ ] **Step 5: Enrich the columnar closing_spec + set `recovery_target=True`**

In `_T1_BERLINCLOCK_COLUMNAR = SyntheticProfile(...)`, replace the columnar layer's `params` list inside `closing_spec` so it carries the executable params alongside the obligation keyword:

```python
                "params": [
                    {"name": "keyword", "values": ["BERLINCLOCK"]},
                    {"name": "width", "values": [11]},
                    {"name": "col_order",
                     "values": [[0, 3, 10, 6, 4, 8, 1, 7, 9, 2, 5]]},
                ],
```

(The `col_order` literal is `keyword_to_order("BERLINCLOCK", 11)`, precomputed and written as an auditable literal.)

Add the argument to the same `SyntheticProfile(...)` call:

```python
    recovery_target=True,
```

Leave `_T1_ABSCISSA_ROUTE` and `_T1_TAPE_K3PT` without `recovery_target` (defaults False).

- [ ] **Step 6: Run the file's tests**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_synthetic_profiles.py -q`
Expected: ALL pass (prior tests + 4 new). If a prior test asserted exact `to_dict` keys, add `recovery_target` to its expectation.

- [ ] **Step 7: Commit**

```bash
git add kryptosbot/synthetic_profiles.py kryptosbot/tests/test_synthetic_profiles.py
git commit -m "feat(synthetic-profiles): recovery_target flag + executable columnar closing_spec"
```

---

## Task 2: `coverage_synthetic.py` — synthetic-CT generator

**Files:**
- Create: `kryptosbot/coverage_synthetic.py`
- Test: `kryptosbot/tests/test_coverage_synthetic.py`

- [ ] **Step 1: Write the failing tests**

Create `kryptosbot/tests/test_coverage_synthetic.py`:

```python
from kryptosbot.coverage_synthetic import (
    CANONICAL_PLAINTEXT,
    generate_synthetic_challenge,
)
from kryptosbot.synthetic_profiles import all_profiles, get_profile


def test_canonical_plaintext_is_97_upper_alpha() -> None:
    assert len(CANONICAL_PLAINTEXT) == 97
    assert CANONICAL_PLAINTEXT.isalpha()
    assert CANONICAL_PLAINTEXT.isupper()


def test_generated_ct_is_97_chars_and_differs_from_pt() -> None:
    for pid in ("T1_SERPENTINE_QUAGMIRE", "T1_BERLINCLOCK_COLUMNAR"):
        spec = get_profile(pid).closing_spec
        ct, cribs = generate_synthetic_challenge(spec)
        assert len(ct) == 97
        assert ct != CANONICAL_PLAINTEXT  # mechanism actually transformed it
        assert len(cribs) == 24


def test_cribs_are_canonical_pt_at_standard_positions() -> None:
    from kryptos.kernel.constants import CRIB_POSITIONS
    spec = get_profile("T1_SERPENTINE_QUAGMIRE").closing_spec
    _, cribs = generate_synthetic_challenge(spec)
    assert set(cribs.keys()) == set(CRIB_POSITIONS)
    for pos in CRIB_POSITIONS:
        assert cribs[pos] == CANONICAL_PLAINTEXT[pos]


def test_round_trip_recovers_plaintext_via_dispatch() -> None:
    # The generated CT, dispatched through the closing_spec (decrypt
    # direction), must recover CANONICAL_PLAINTEXT exactly — proving the
    # generator's encrypt is the true inverse of the dispatched decrypt.
    from kryptosbot import job_dispatcher
    for pid in ("T1_SERPENTINE_QUAGMIRE", "T1_BERLINCLOCK_COLUMNAR"):
        spec = get_profile(pid).closing_spec
        ct, cribs = generate_synthetic_challenge(spec)
        result = job_dispatcher.execute_from_json(
            spec, challenge_ciphertext=ct, challenge_crib_dict=cribs,
            bench_mode=True, parallel=False,
        )
        # All 24 cribs recovered -> crib_score 24.
        assert result.best_score == 24, (pid, result.best_score)


def test_multi_layer_spec_rejected() -> None:
    import pytest
    two_layer = {
        "hypothesis_id": "two",
        "pipeline": [
            {"kind": "atbash", "alphabet": "AZ", "params": []},
            {"kind": "atbash", "alphabet": "AZ", "params": []},
        ],
        "compute_budget_cpu_minutes": 30,
    }
    with pytest.raises(ValueError):
        generate_synthetic_challenge(two_layer)
```

NOTE on `execute_from_json`: verified `execute_from_json(raw, **kwargs)` forwards all kwargs to `execute` verbatim (incl. `challenge_ciphertext`/`challenge_crib_dict`/`bench_mode`/`parallel`), and accepts a dict, so the test works as written. It first runs `validate_hypothesis_spec(raw)`; if that proves stricter than expected for the enriched columnar spec (it should not — it validates DSL shape, not translator params), fall back to `job_dispatcher.execute(HypothesisSpec.from_dict(spec), challenge_ciphertext=ct, challenge_crib_dict=cribs, bench_mode=True, parallel=False)`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_coverage_synthetic.py -q`
Expected: FAIL — module `kryptosbot.coverage_synthetic` does not exist (ImportError).

- [ ] **Step 3: Create the module**

Create `kryptosbot/coverage_synthetic.py`:

```python
"""Synthetic-CT generator for coverage recovery (PR 3).

Generates a synthetic ciphertext from a profile's closing_spec by reusing
the dispatcher's spec->pipeline translation in ENCRYPT direction, applied
to a fixed canonical plaintext. Because the SAME translation produces the
decrypt pipeline that execute() runs, encrypt and decrypt are true
inverses: dispatching the closing_spec against the generated CT recovers
the canonical plaintext, so crib_score reaches 24 (>= SIGNAL).

The real K4 ciphertext is never used: the CT is produced from
CANONICAL_PLAINTEXT via the mechanism. Crib positions reuse the kernel's
canonical CRIB_POSITIONS (integer indices only — not the real CT).
"""

from __future__ import annotations

from typing import Any

# A fixed 97-letter A-Z plaintext. The exact text is irrelevant; the
# invariant (97 uppercase letters) is enforced by tests. The mechanism,
# not the plaintext, is what varies per profile.
CANONICAL_PLAINTEXT = (
    "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    "THEQUICKBROWNFOXJUMPSOVERTH"
)  # 35 + 35 + 27 = 97


def generate_synthetic_challenge(
    closing_spec: dict[str, Any],
) -> tuple[str, dict[int, str]]:
    """Return (synthetic_ct, crib_dict) for a single-layer closing_spec.

    Reuses the dispatcher translation in encrypt direction. Raises
    ValueError for multi-layer specs (out of scope; recovery targets are
    single-layer).
    """
    from kryptos.kernel.constants import CRIB_POSITIONS
    from kryptos.kernel.transforms.compose import (
        PipelineConfig,
        TransformConfig,
        TransformType,
        build_pipeline,
    )
    from kryptosbot import job_dispatcher
    from kryptosbot.hypothesis_dsl import HypothesisSpec

    spec = HypothesisSpec.from_dict(closing_spec)
    spec = job_dispatcher._expand_procedural_layers(spec)
    if len(spec.pipeline) != 1:
        raise ValueError(
            f"generate_synthetic_challenge supports single-layer specs only; "
            f"got {len(spec.pipeline)} layers (multi-layer encrypt-order is "
            f"out of scope for PR3)"
        )

    bindings_list = list(job_dispatcher._enumerate_bindings(spec))
    if len(bindings_list) != 1:
        raise ValueError(
            f"closing_spec must pin a single config; got "
            f"{len(bindings_list)} bindings"
        )
    pipeline_dict = job_dispatcher._build_pipeline_config(
        spec, bindings_list[0], text_length=len(CANONICAL_PLAINTEXT),
    )

    # build_pipeline ignores PipelineConfig.direction; the encrypt branch
    # is selected per-step via params["direction"]="encrypt" (non-"undo"
    # for transposition, non-"decrypt" for vigenere/quagmire/bifid).
    steps = []
    for s in pipeline_dict["steps"]:
        params = dict(s.get("params", {}))
        params["direction"] = "encrypt"
        steps.append(
            TransformConfig(
                transform_type=TransformType(s["type"]),
                params=params,
                description=s.get("description", ""),
            )
        )
    pipeline = PipelineConfig(
        name=pipeline_dict["name"] + "__encrypt",
        steps=tuple(steps),
        direction="encrypt",
    )
    fn = build_pipeline(pipeline)
    ct = fn(CANONICAL_PLAINTEXT)
    if len(ct) != len(CANONICAL_PLAINTEXT):
        raise ValueError(
            f"synthetic CT length {len(ct)} != PT length "
            f"{len(CANONICAL_PLAINTEXT)}"
        )

    crib_dict = {pos: CANONICAL_PLAINTEXT[pos] for pos in CRIB_POSITIONS}
    return (ct, crib_dict)


__all__ = ["CANONICAL_PLAINTEXT", "generate_synthetic_challenge"]
```

- [ ] **Step 4: Run the tests**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_coverage_synthetic.py -q`
Expected: PASS (5 tests). If `test_round_trip_recovers_plaintext_via_dispatch` shows `best_score < 24`, the encrypt/decrypt are not true inverses — STOP and debug the per-step `direction` handling (do not weaken the assertion). Likely causes: a step type whose encrypt branch needs a value other than `"encrypt"`, or a translator that hard-codes `direction` in its emitted params (inspect `_translate_layer` output for that kind).

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/coverage_synthetic.py kryptosbot/tests/test_coverage_synthetic.py
git commit -m "feat(coverage-synthetic): generate synthetic CT via encrypt-direction round-trip"
```

---

## Task 3: scheduler recovery-target scoring path (fail-closed)

**Files:**
- Modify: `kryptosbot/coverage_scheduler.py`
- Test: `kryptosbot/tests/test_coverage_scheduler.py`

- [ ] **Step 1: Write the failing tests**

Add to `kryptosbot/tests/test_coverage_scheduler.py`:

```python
def test_recovery_target_reaches_satisfied_via_scoring() -> None:
    from kryptosbot.coverage_audit import (
        CoverageAuditCollector, REJECTION_CAUSE_SATISFIED,
    )
    for pid in ("T1_SERPENTINE_QUAGMIRE", "T1_BERLINCLOCK_COLUMNAR"):
        profile = get_profile(pid)
        collector = CoverageAuditCollector(profile=profile)
        report = run_coverage_schedule(
            profile, collector, project_root=Path("/home/cpatrick/kryptos"),
        )
        causes = [o["cause"] for o in report.per_obligation]
        assert REJECTION_CAUSE_SATISFIED in causes, (pid, causes)
        assert report.passed is True, pid
        assert report.best_score == 24, (pid, report.best_score)


def test_route_stays_emitted_and_admissible() -> None:
    from kryptosbot.coverage_audit import (
        CoverageAuditCollector, REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE,
    )
    profile = get_profile("T1_ABSCISSA_ROUTE")
    assert profile.recovery_target is False
    collector = CoverageAuditCollector(profile=profile)
    report = run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE in causes
    assert report.passed is True


def test_recovery_target_fail_closed_on_generation_error(monkeypatch) -> None:
    # If CT generation raises for a recovery target, the report must FAIL
    # (not silently downgrade to emitted_and_admissible).
    import kryptosbot.coverage_scheduler as cs
    from kryptosbot.coverage_audit import (
        CoverageAuditCollector, REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE,
    )

    def _boom(_spec):
        raise RuntimeError("synthetic generation broke")

    monkeypatch.setattr(cs, "generate_synthetic_challenge", _boom)
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    collector = CoverageAuditCollector(profile=profile)
    report = run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    assert report.passed is False
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE not in causes
    assert any("synthetic generation broke" in r or "recovery" in r.lower()
               for r in report.fail_reasons), report.fail_reasons


def test_recovery_target_dispatches_with_challenge_ct(monkeypatch) -> None:
    # The recovery path must call execute with a non-None challenge_ciphertext
    # (so the kernel CT is never the input).
    import kryptosbot.job_dispatcher as jd
    from kryptosbot.coverage_audit import CoverageAuditCollector
    seen = {}
    real_execute = jd.execute

    def _spy(spec, **kw):
        seen["challenge_ciphertext"] = kw.get("challenge_ciphertext")
        return real_execute(spec, **kw)

    monkeypatch.setattr(jd, "execute", _spy)
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    collector = CoverageAuditCollector(profile=profile)
    run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    assert seen["challenge_ciphertext"] is not None
    assert len(seen["challenge_ciphertext"]) == 97
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_coverage_scheduler.py -k "recovery_target or route_stays" -q`
Expected: FAIL — the scheduler currently runs admissibility-only for all available profiles, so recovery targets reach `emitted_and_admissible`, not `satisfied`; `report.best_score` is 0.

- [ ] **Step 3: Implement the recovery-target branch**

In `kryptosbot/coverage_scheduler.py`, add the import near the top (module level is fine — `coverage_synthetic` has no heavy import-time cost):

```python
from kryptosbot.coverage_synthetic import generate_synthetic_challenge
```

In `run_coverage_schedule`, after the blocked-profile and self-consistency guards (i.e. once the profile is available and its closing_spec is self-consistent), replace the single emit+admissibility block with a branch on `recovery_target`. The non-recovery path is the EXISTING PR2 emit + `check_spec_admissibility` + `record_dispatcher_outcome(admissibility_only=True, ...)` logic. Add the recovery path:

```python
    spec_dict = profile.closing_spec or {}
    hyp_id = spec_dict.get("hypothesis_id", f"{profile.profile_id}__closing")
    family = profile.obligations[0].expected_family if profile.obligations else ""

    if profile.recovery_target:
        from kryptosbot import job_dispatcher
        from kryptosbot.hypothesis_dsl import HypothesisSpec
        collector.record_emitted_spec(
            hypothesis_id=hyp_id,
            title=f"{profile.profile_id} recovery-target closing spec",
            family=family,
            layers=list(spec_dict.get("pipeline") or []),
            origin="coverage_scheduler",
        )
        try:
            ct, cribs = generate_synthetic_challenge(spec_dict)
            result = job_dispatcher.execute(
                HypothesisSpec.from_dict(spec_dict),
                challenge_ciphertext=ct,
                challenge_crib_dict=cribs,
                bench_mode=True,
                parallel=False,
            )
        except Exception as exc:  # fail-closed: never downgrade to admissible
            reason = (
                f"coverage-scheduler recovery FAILED for "
                f"{profile.profile_id!r}: {exc}"
            )
            collector.add_note(reason)
            collector.forced_fail_reason = reason
            return collector.build_report()
        collector.record_dispatcher_outcome(
            hypothesis_id=hyp_id,
            admissibility_verdict=result.admissibility_verdict or "ok",
            admissibility_reasons=list(result.admissibility_reasons),
            total_tested=result.total_tested,
            best_score=result.best_score,
            admissibility_only=False,
        )
        return collector.build_report()

    # --- non-recovery-target (route): PR2 emitted+admissible path (unchanged) ---
    collector.record_emitted_spec(
        hypothesis_id=hyp_id,
        title=f"{profile.profile_id} deterministic closing spec",
        family=family,
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
```

Preserve the existing blocked-profile and self-consistency-failure early returns exactly as they are (do not alter PR2 behavior for those). Only the available-profile tail is split into the recovery vs non-recovery branches above. If `result.admissibility_verdict` comes back `"rejected"` for a recovery target (shouldn't, since the spec is executable), the recorded outcome will naturally yield `emitted_but_admissibility_rejected` via the PR1 ladder — acceptable (it's a real rejection, not a downgrade).

- [ ] **Step 4: Run the scheduler + audit tests**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_coverage_scheduler.py kryptosbot/tests/test_coverage_audit.py -q`
Expected: ALL pass, including the 4 new tests and the existing PR2 ones (blocked refusal, route emitted+admissible, etc.).

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/coverage_scheduler.py kryptosbot/tests/test_coverage_scheduler.py
git commit -m "feat(coverage-scheduler): recovery-target scoring branch (fail-closed)"
```

---

## Task 4: end-to-end smoke + full-suite verification

**Files:** none (verification only)

- [ ] **Step 1: Record real ledger mtime, run the quagmire scheduler smoke**

Run:

```bash
cd /home/cpatrick/kryptos
ls -la --time-style=+%H:%M:%S db/theory_ledger.sqlite
PYTHONPATH=src python3 -u kryptosbot/run_controller.py \
  --synthetic-profile T1_SERPENTINE_QUAGMIRE \
  --coverage-scheduler-enabled \
  --cycles 1 \
  --coverage-report results/coverage_reports/
```

Expected: exits 0; prints `coverage-report: wrote artifact -> .../<ts>_T1_SERPENTINE_QUAGMIRE_coverage_report.json`.

- [ ] **Step 2: Inspect the report — now `satisfied`, not just admissible**

Run:

```bash
PYTHONPATH=src python3 -c "
import json, glob, os
f = sorted(glob.glob('results/coverage_reports/*T1_SERPENTINE_QUAGMIRE*'), key=os.path.getmtime)[-1]
d = json.load(open(f))
print('schema:', d['schema_version'])
print('pass:', d['pass'])
print('best_score:', d['best_score'])
print('ledger:', d['ledger_db_path'])
for o in d['per_obligation']:
    print(o['obligation'], '->', o['cause'])
"
```

Expected: `schema: coverage_report.v2`; `pass: True`; `best_score: 24`; ledger under `db/synthetic_profiles/`; obligation cause `satisfied`.

- [ ] **Step 3: Confirm real ledger untouched**

Run: `ls -la --time-style=+%H:%M:%S db/theory_ledger.sqlite`
Expected: mtime unchanged from Step 1.

- [ ] **Step 4: Rebuild null baselines at current HEAD, then run full suite**

Committing Tasks 1-3 moved HEAD, which re-stales the commit-pinned null baselines (a known repo characteristic). Rebuild, then run the suite:

```bash
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py >/dev/null 2>&1 && echo "standard rebuilt"
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines_r2_4.py >/dev/null 2>&1 && echo "r2_4 rebuilt"
PYTHONPATH=src /home/cpatrick/kryptos/venv/bin/python -m pytest kryptosbot/tests/ -q -n 26
```

Expected: full suite green (the 5 pre-existing `test_priority5` failures were fixed in commit `dc03a20`; only a green run with the new PR3 tests should remain). Leave `null_baselines/manifest.json` UNCOMMITTED (re-pinned to current HEAD; committing it would re-stale — matches repo convention).

- [ ] **Step 5: Commit any final adjustment (only if Step 4 surfaced a PR3-caused failure)**

```bash
git add <fixed files>
git commit -m "test(coverage-recovery): fix <specific issue>"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** §4.1 `recovery_target` + columnar enrichment → Task 1; §4.2 generator (`CANONICAL_PLAINTEXT`, `generate_synthetic_challenge`, per-step encrypt direction, single-layer guard, CRIB_POSITIONS) → Task 2; §4.3 scheduler recovery branch + fail-closed → Task 3; §4.4 no run_controller change → respected (no Task touches it); §5 safety invariants → asserted in Task 2 (round-trip, no real CT) + Task 3 (challenge_ciphertext spy, fail-closed) + Task 4 (real ledger untouched); §6 tests → Tasks 1-3 tests + Task 4 smoke; §3 closure-via-PR1-ladder → Task 3 records total_tested/best_score so PR1 yields satisfied/tested_no_signal; §3.5 route stays emitted+admissible → Task 3 non-recovery branch + `test_route_stays_emitted_and_admissible`; §7 NOT-in-scope → multi-layer guard (Task 2), route unchanged, T1_TAPE_K3PT untouched.
- **Placeholder scan:** no TBD/TODO. The one conditional ("if execute_from_json doesn't forward challenge inputs, use execute") is a concrete either/or with both code paths named, not a placeholder — the implementer picks the one that forwards challenge inputs after reading the signature.
- **Type consistency:** `generate_synthetic_challenge(closing_spec: dict) -> tuple[str, dict[int,str]]`, `CANONICAL_PLAINTEXT` (97-char str), `recovery_target` bool, `forced_fail_reason` (from PR2), `JobResult.best_score`/`.total_tested`/`.admissibility_verdict`/`.admissibility_reasons`, and `REJECTION_CAUSE_SATISFIED`/`REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE` are used consistently across tasks. The columnar `col_order` literal `[0,3,10,6,4,8,1,7,9,2,5]` is identical in Task 1 source and Task 1 test.
