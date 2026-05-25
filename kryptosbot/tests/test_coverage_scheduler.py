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
