"""Tests for kryptosbot.coverage_audit.

PR 1 (2026-05-17) test surface for the per-run coverage audit artifact.
The tests pin five invariants:

1. The artifact is written even when the run fails the profile pass
   condition (i.e. on FAIL, not just on PASS).
2. The report has ``obligation_closure_rate`` in its counts block.
3. The report distinguishes ``emitted_but_critic_rejected`` from
   ``emitted_but_admissibility_rejected`` and from ``halted_before_dispatch``.
4. The schema version is pinned.
5. The T1 postmortem regression: a synthetic-profile run that fails to
   emit the SERPENTINE obligation produces an explicit
   "expected obligation not emitted: ..." fail reason — never a silent
   pass.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryptosbot.coverage_audit import (
    REJECTION_CAUSE_ADMISSIBILITY_REJECTED,
    REJECTION_CAUSE_CRITIC_REJECTED,
    REJECTION_CAUSE_EXHAUSTION_OVERLAP,
    REJECTION_CAUSE_HALTED_BEFORE_DISPATCH,
    REJECTION_CAUSE_NEVER_EMITTED,
    REJECTION_CAUSE_SATISFIED,
    REJECTION_CAUSE_TESTED_NO_SIGNAL,
    SCHEMA_VERSION,
    CoverageAuditCollector,
    build_collector_for_profile,
    resolve_report_path,
    write_report,
)
from kryptosbot.synthetic_profiles import get_profile


# ─── Fixtures ───────────────────────────────────────────────────────────────


SERPENTINE_QUAG_LAYER = {
    "kind": "quagmire",
    "alphabet": "AZ",
    "params": [
        {"name": "variant", "values": ["quagmire_iii"]},
        {"name": "period_keyword", "values": ["SERPENTINE"]},
    ],
    "recipe_id": None,
}

# A spec that names SERPENTINE on a Vigenere keyword axis — exactly the
# T1 postmortem "laundered the obligation through a different parameter"
# failure mode. This MUST NOT satisfy the quagmire obligation.
LAUNDERED_VIG_LAYER = {
    "kind": "vigenere",
    "alphabet": "AZ",
    "params": [
        {"name": "keyword", "values": ["SERPENTINE"]},
    ],
    "recipe_id": None,
}


def _fresh_collector() -> CoverageAuditCollector:
    return build_collector_for_profile("T1_SERPENTINE_QUAGMIRE")


# ─── Tests ──────────────────────────────────────────────────────────────────


def test_schema_version_is_pinned() -> None:
    """Schema bumps require an explicit version change."""
    assert SCHEMA_VERSION == "coverage_report.v1"


def test_empty_run_fails_with_never_emitted() -> None:
    """No specs at all → never_emitted, not silent pass."""
    c = _fresh_collector()
    report = c.build_report()
    assert report.passed is False
    assert report.matched_expected_obligation is False
    # Per-obligation cause is "obligation_not_emitted"
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_NEVER_EMITTED in causes
    # Fail reasons contain the human-readable text the regression test
    # below also checks.
    assert any(
        "expected obligation not emitted" in r for r in report.fail_reasons
    )


def test_laundered_vigenere_spec_does_not_satisfy_obligation() -> None:
    """The T1 postmortem mode: SERPENTINE on a vigenere keyword does
    NOT satisfy the quagmire_iii period_keyword obligation.
    """
    c = _fresh_collector()
    c.record_emitted_spec(
        hypothesis_id="hLAUNDER", title="vig SERP", family="vigenere",
        layers=[LAUNDERED_VIG_LAYER],
    )
    report = c.build_report()
    assert report.passed is False
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_NEVER_EMITTED in causes


def test_critic_rejection_is_distinguishable_from_admissibility() -> None:
    """When a matching spec is emitted but critic rejects it, the cause
    must say 'critic_rejected', NOT 'admissibility_rejected'.
    """
    c = _fresh_collector()
    c.record_emitted_spec(
        hypothesis_id="hX", title="t", family="quagmire_iii",
        layers=[SERPENTINE_QUAG_LAYER],
    )
    c.record_critic_outcome(
        hypothesis_id="hX", decision="reject_duplicate", reasons=["dup"],
    )
    report = c.build_report()
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_CRITIC_REJECTED in causes
    assert REJECTION_CAUSE_ADMISSIBILITY_REJECTED not in causes


def test_admissibility_rejection_path() -> None:
    """Critic approves but admissibility rejects → admissibility cause."""
    c = _fresh_collector()
    c.record_emitted_spec(
        hypothesis_id="hY", title="t", family="quagmire_iii",
        layers=[SERPENTINE_QUAG_LAYER],
    )
    c.record_critic_outcome(hypothesis_id="hY", decision="approve")
    c.record_dispatcher_outcome(
        hypothesis_id="hY",
        admissibility_verdict="rejected",
        admissibility_reasons=["budget exceeded"],
    )
    report = c.build_report()
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_ADMISSIBILITY_REJECTED in causes


def test_exhaustion_overlap_distinguishable_from_other_admissibility() -> None:
    """Exhaustion-overlap admissibility rejection is its own cause."""
    c = _fresh_collector()
    c.record_emitted_spec(
        hypothesis_id="hZ", title="t", family="quagmire_iii",
        layers=[SERPENTINE_QUAG_LAYER],
    )
    c.record_critic_outcome(hypothesis_id="hZ", decision="approve")
    c.record_dispatcher_outcome(
        hypothesis_id="hZ",
        admissibility_verdict="rejected",
        admissibility_reasons=["exhaustion overlap: 5 prior entries"],
    )
    report = c.build_report()
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_EXHAUSTION_OVERLAP in causes
    assert REJECTION_CAUSE_ADMISSIBILITY_REJECTED not in causes


def test_halted_before_dispatch_distinct_from_admissibility() -> None:
    """No critic + no dispatcher record == halted_before_dispatch.

    This is the dry-run path. Reporting it as admissibility-rejected
    would be a lie (no admissibility check actually ran).
    """
    c = _fresh_collector()
    c.record_emitted_spec(
        hypothesis_id="hH", title="t", family="quagmire_iii",
        layers=[SERPENTINE_QUAG_LAYER],
    )
    # No critic outcome, no dispatcher outcome.
    report = c.build_report()
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_HALTED_BEFORE_DISPATCH in causes


def test_tested_no_signal_distinct_from_satisfied() -> None:
    """Tested + below signal threshold → tested_but_no_signal."""
    c = _fresh_collector()
    c.record_emitted_spec(
        hypothesis_id="hT", title="t", family="quagmire_iii",
        layers=[SERPENTINE_QUAG_LAYER],
    )
    c.record_critic_outcome(hypothesis_id="hT", decision="approve")
    c.record_dispatcher_outcome(
        hypothesis_id="hT",
        admissibility_verdict="ok",
        total_tested=1000,
        best_score=5.0,  # below default signal threshold of 18
    )
    report = c.build_report()
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_TESTED_NO_SIGNAL in causes
    assert REJECTION_CAUSE_SATISFIED not in causes
    assert report.passed is False  # below signal threshold still fails


def test_satisfied_when_signal_reached() -> None:
    c = _fresh_collector()
    c.record_emitted_spec(
        hypothesis_id="hS", title="t", family="quagmire_iii",
        layers=[SERPENTINE_QUAG_LAYER],
    )
    c.record_critic_outcome(hypothesis_id="hS", decision="approve")
    c.record_dispatcher_outcome(
        hypothesis_id="hS",
        admissibility_verdict="ok",
        total_tested=1000,
        best_score=24.0,
    )
    report = c.build_report()
    assert report.passed is True
    causes = [o["cause"] for o in report.per_obligation]
    assert REJECTION_CAUSE_SATISFIED in causes


def test_obligation_closure_rate_in_counts() -> None:
    """counts['obligation_closure_rate'] must be present."""
    c = _fresh_collector()
    report = c.build_report()
    assert "obligation_closure_rate" in report.counts
    # No obligations met → 0.0
    assert report.counts["obligation_closure_rate"] == pytest.approx(0.0)


def test_obligation_closure_rate_increments_on_satisfaction() -> None:
    c = _fresh_collector()
    c.record_emitted_spec(
        hypothesis_id="hS", title="t", family="quagmire_iii",
        layers=[SERPENTINE_QUAG_LAYER],
    )
    c.record_critic_outcome(hypothesis_id="hS", decision="approve")
    c.record_dispatcher_outcome(
        hypothesis_id="hS", admissibility_verdict="ok",
        total_tested=1, best_score=24.0,
    )
    report = c.build_report()
    assert report.counts["obligation_closure_rate"] == pytest.approx(1.0)


def test_report_written_on_pass(tmp_path: Path) -> None:
    c = _fresh_collector()
    c.record_emitted_spec(
        hypothesis_id="hS", title="t", family="quagmire_iii",
        layers=[SERPENTINE_QUAG_LAYER],
    )
    c.record_critic_outcome(hypothesis_id="hS", decision="approve")
    c.record_dispatcher_outcome(
        hypothesis_id="hS", admissibility_verdict="ok",
        total_tested=1, best_score=24.0,
    )
    path = tmp_path / "pass_report.json"
    written = c.write_report(path)
    assert written == path
    data = json.loads(path.read_text())
    assert data["pass"] is True
    assert data["schema_version"] == SCHEMA_VERSION


def test_report_written_on_fail(tmp_path: Path) -> None:
    """Failing to emit the report is the PR-1 failure mode this prevents."""
    c = _fresh_collector()  # no events recorded
    path = tmp_path / "fail_report.json"
    written = c.write_report(path)
    assert written.exists()
    data = json.loads(path.read_text())
    assert data["pass"] is False
    # The fail_reasons array must explicitly say "expected obligation
    # not emitted" — this is the T1 postmortem-shaped regression check.
    assert any(
        "expected obligation not emitted" in r for r in data["fail_reasons"]
    )


def test_t1_postmortem_regression(tmp_path: Path) -> None:
    """T1 postmortem regression: emitted spec laundering SERPENTINE
    onto a vigenere layer must produce the explicit "not emitted"
    fail reason on the quagmire_iii / period_keyword axis.

    Equivalent text required by the brief:
      "expected obligation not emitted:
       quagmire.period_keyword=SERPENTINE"
    """
    c = _fresh_collector()
    c.record_emitted_spec(
        hypothesis_id="h_postmortem", title="vig keyword=SERP",
        family="vigenere", layers=[LAUNDERED_VIG_LAYER],
    )
    c.record_critic_outcome(
        hypothesis_id="h_postmortem", decision="approve",
    )
    c.record_dispatcher_outcome(
        hypothesis_id="h_postmortem",
        admissibility_verdict="ok",
        total_tested=500, best_score=4.0,
    )
    path = tmp_path / "postmortem.json"
    c.write_report(path)
    data = json.loads(path.read_text())
    assert data["pass"] is False
    # The literal text the user's brief requires.
    fail_text = " ".join(data["fail_reasons"])
    assert "expected obligation not emitted" in fail_text
    assert "quagmire" in fail_text.lower()
    assert "period_keyword" in fail_text.lower()
    assert "SERPENTINE" in fail_text
    # Spec-level: missing_expected_obligations names the obligation,
    # not paraphrased.
    missing = " ".join(data["missing_expected_obligations"])
    assert "quagmire" in missing
    assert "SERPENTINE" in missing


def test_resolve_report_path_directory_form(tmp_path: Path) -> None:
    """Directory form: filename is stamped with profile id."""
    path = resolve_report_path(
        profile_id="T1_SERPENTINE_QUAGMIRE",
        coverage_report_arg=str(tmp_path),
        project_root=Path("/unused"),
    )
    assert path.parent == tmp_path
    assert path.name.endswith("_T1_SERPENTINE_QUAGMIRE_coverage_report.json")


def test_resolve_report_path_file_form(tmp_path: Path) -> None:
    """File form: arg ending in .json is treated as the full path."""
    target = tmp_path / "custom.json"
    path = resolve_report_path(
        profile_id="T1_SERPENTINE_QUAGMIRE",
        coverage_report_arg=str(target),
        project_root=Path("/unused"),
    )
    assert path == target


def test_resolve_report_path_default(tmp_path: Path) -> None:
    """No arg → results/coverage_reports/ under project_root."""
    path = resolve_report_path(
        profile_id="T1_SERPENTINE_QUAGMIRE",
        coverage_report_arg=None,
        project_root=tmp_path,
    )
    assert "coverage_reports" in path.parts
    assert path.parent.parent == tmp_path / "results"


def test_collector_methods_swallow_internal_errors(tmp_path: Path) -> None:
    """A malformed layer must not crash the collector — best-effort policy."""
    c = _fresh_collector()
    # An exotic layer object the flattener can't introspect.
    c.record_emitted_spec(
        hypothesis_id="hM", title="t", family="q", layers=[object()],
    )
    # No exception — record was still appended with a "_warning" marker.
    assert len(c.emitted_specs) == 1
    assert c.emitted_specs[0].layers[0].get("_warning")


def test_write_report_is_atomic(tmp_path: Path) -> None:
    """write_report uses tmp-file + rename — no half-written JSON if
    the process is interrupted mid-write."""
    c = _fresh_collector()
    path = tmp_path / "atomic.json"
    c.write_report(path)
    # The temp file must not survive a successful write.
    assert path.exists()
    assert not (tmp_path / "atomic.json.tmp").exists()


def test_synthetic_mode_flag_recorded_on_report() -> None:
    """The artifact must reflect that we were in synthetic mode."""
    c = _fresh_collector()
    assert c.synthetic_mode is True
    report = c.build_report()
    assert report.synthetic_mode is True
