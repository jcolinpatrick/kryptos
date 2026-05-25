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
spec would mean running against the real K4 CT - out of scope and
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
        report = collector.build_report()
        # Surface the refusal in fail_reasons so callers (and the PR1
        # report contract) see an explicit "blocked" cause, not only the
        # generic "no obligations" guard. The scheduler refuses blocked
        # profiles by construction, mirroring PR1's launch refusal.
        report.passed = False
        report.fail_reasons.append(
            f"coverage-scheduler refused blocked profile "
            f"{profile.profile_id!r}: {profile.blocked_reason}"
        )
        return report

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
