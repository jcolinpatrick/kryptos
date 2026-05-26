"""Deterministic coverage scheduler for synthetic profiles (PR 2/PR 3).

PR 1 made coverage failure observable; PR 2 closed obligations by
construction; PR 3 adds scoring for recovery targets. When
--coverage-scheduler-enabled, this module builds the profile's explicit
closing_spec and either:

  * (recovery_target=False, e.g. route) proves it is EMITTED + ADMISSIBLE:
    runs only the dispatcher's pre-kernel preamble
    (_expand_procedural_layers -> check_admissibility) and records the
    verdict through the PR1 collector. It never calls
    job_dispatcher.execute or any kernel scoring path for these profiles.

  * (recovery_target=True, e.g. serpentine/columnar) GENERATES a synthetic
    97-char ciphertext from the closing_spec (coverage_synthetic), then
    dispatches the spec against that SYNTHETIC CT via
    job_dispatcher.execute(bench_mode=True) and records the real
    best_score. The PR1 ladder reaches `satisfied` when best_score>=18.
    Fail-closed: any generation/dispatch failure on a recovery target is
    a HARD failure (forced_fail_reason), never a downgrade to
    emitted_and_admissible.

It never runs against the real K4 CT (recovery-target dispatch uses the
synthetic CT only), never touches the real ledger, and makes no LLM/API
call. Blocked profiles (T1_TAPE_K3PT) are refused, mirroring PR1's launch
refusal.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from kryptosbot.coverage_audit import CoverageAuditCollector, CoverageReport
from kryptosbot.coverage_synthetic import generate_synthetic_challenge
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

    project_root is accepted for caller-signature symmetry (run_controller
    passes it; the report is written to disk by the caller, not here).
    """
    collector.add_note("coverage-scheduler: Approach A (emitted+admissible, no execution)")

    if profile.status == "blocked":
        # Surface a single clear blocked cause through the collector so it
        # flows via build_report() into BOTH the returned report and any
        # subsequently-persisted artifact (the controller persists via
        # collector.write_report, which re-runs build_report and would
        # otherwise re-derive the generic "no obligations" guard). The
        # scheduler refuses blocked profiles by construction, mirroring
        # PR1's launch refusal.
        reason = (
            f"coverage-scheduler refused blocked profile "
            f"{profile.profile_id!r}: {profile.blocked_reason}"
        )
        collector.add_note(reason)
        collector.forced_fail_reason = reason
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
    family = profile.obligations[0].expected_family if profile.obligations else ""

    if profile.recovery_target:
        # PR3: recovery targets are SCORED, not stopped at the
        # admissibility boundary. Generate a synthetic CT from the
        # closing_spec, dispatch the spec against it (bench_mode isolates
        # the synthetic profile from real-K4 surfaces), and record the
        # real best_score so the PR1 ladder can reach `satisfied`.
        # Fail-closed: any generation/dispatch failure on a recovery
        # target is a hard failure - NEVER a silent downgrade to
        # emitted_and_admissible.
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


__all__ = [
    "check_spec_admissibility",
    "run_coverage_schedule",
    "verify_profile_closing_spec",
]
