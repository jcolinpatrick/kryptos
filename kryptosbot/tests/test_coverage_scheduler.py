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
            {"name": "keyword", "values": ["BERLINCLOCK"]}
        ]}],
        "compute_budget_cpu_minutes": 30,
    }
    verdict, reasons = check_spec_admissibility(bad)
    assert verdict == "rejected"
    assert reasons


def test_run_coverage_schedule_closes_serpentine() -> None:
    # PR3: T1_SERPENTINE_QUAGMIRE is a recovery_target, so the scheduler
    # now SCORES it (synthetic CT + dispatch) rather than stopping at the
    # admissibility boundary. It reaches `satisfied`, not
    # `emitted_and_admissible`.
    from kryptosbot.coverage_audit import (
        CoverageAuditCollector,
        REJECTION_CAUSE_SATISFIED,
    )
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    collector = CoverageAuditCollector(profile=profile)
    report = run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_SATISFIED in causes
    assert report.passed is True


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


def test_run_coverage_schedule_refuses_blocked() -> None:
    profile = get_profile("T1_TAPE_K3PT")
    from kryptosbot.coverage_audit import CoverageAuditCollector
    collector = CoverageAuditCollector(profile=profile)
    report = run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    assert report.passed is False
    assert any("blocked" in r.lower() for r in report.fail_reasons)


def test_blocked_profile_reason_persists_to_artifact(tmp_path) -> None:
    # The curated blocked reason must survive a write_report/build_report
    # round-trip (the controller persists via collector.write_report, NOT
    # the run_coverage_schedule return value).
    import json
    from kryptosbot.coverage_audit import CoverageAuditCollector
    profile = get_profile("T1_TAPE_K3PT")
    collector = CoverageAuditCollector(profile=profile)
    run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    out = tmp_path / "report.json"
    collector.write_report(out)
    d = json.loads(out.read_text())
    assert d["pass"] is False
    assert any("blocked" in r.lower() for r in d["fail_reasons"]), d["fail_reasons"]


def test_run_coverage_schedule_never_executes_kernel(monkeypatch) -> None:
    # PR3: only recovery_target profiles dispatch the kernel. A
    # non-recovery-target (route) keeps the PR2 admissibility-only path
    # and must NEVER call execute().
    import kryptosbot.job_dispatcher as jd
    called = {"execute": False}

    def _boom(*a, **k):
        called["execute"] = True
        raise AssertionError("execute() must NOT be called by the scheduler")

    monkeypatch.setattr(jd, "execute", _boom)
    profile = get_profile("T1_ABSCISSA_ROUTE")
    assert profile.recovery_target is False
    from kryptosbot.coverage_audit import CoverageAuditCollector
    collector = CoverageAuditCollector(profile=profile)
    run_coverage_schedule(
        profile, collector, project_root=Path("/home/cpatrick/kryptos"),
    )
    assert called["execute"] is False
