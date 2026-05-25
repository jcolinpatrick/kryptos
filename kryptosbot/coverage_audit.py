"""Per-run coverage audit artifact for synthetic profile runs.

PR 1 (2026-05-17) scope: capture, per synthetic-profile run, *exactly*
why the controller did or did not satisfy the profile's obligations.
The artifact is written even when the controller halts early or every
candidate is rejected — failing silently was the T1 postmortem failure
mode this module exists to prevent.

The key diagnostic the artifact must support is distinguishing among:

  1. **expected obligation never emitted**     — no spec ever proposed
     the required (kind, variant, parameter, value) combination
  2. **emitted but critic rejected**           — at least one spec
     matched the obligation, but the critic rejected every such spec
  3. **emitted and critic-approved but dispatcher rejected**
     — admissibility failed for every matching spec (budget,
     translation, or structural)
  4. **dispatcher rejected due to exhaustion overlap**
     — a narrower sibling of (3): admissibility specifically caught a
     real-K4 exhaustion-log overlap (this is mostly suppressed in
     synthetic mode, but recorded so the operator can see it)
  5. **dispatched/tested but no signal**       — at least one matching
     spec actually ran through the kernel and produced results, but
     `best_score` was below SIGNAL_THRESHOLD

The collector lives in the controller process. It is wired in by
``run_controller.py`` when ``--synthetic-profile`` is given. The
controller passes the collector to ``ControllerConfig.coverage_collector``
and the dispatch + critic + theorist paths emit events through the
collector's ``record_*`` methods. Everything is best-effort: a raising
collector callback never fails the cycle.

Artifact schema lives in ``CoverageReport.to_dict``. The schema version
is pinned at ``schema_version="coverage_report.v1"`` for downstream
parsers. A schema bump requires a new version string and a migration
note in this docstring.

v2 (2026-05-25): adds the emitted_and_admissible cause and the
DispatcherOutcomeRecord.admissibility_only field for the deterministic
coverage scheduler. v1 parsers remain valid for v1 artifacts.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from kryptosbot.synthetic_profiles import (
    ParameterObligation,
    SyntheticProfile,
    get_profile,
)


logger = logging.getLogger("kryptosbot.coverage_audit")


# ─── Constants ──────────────────────────────────────────────────────────────


SCHEMA_VERSION = "coverage_report.v2"


# Default signal threshold mirrors the kernel scoring layer's SIGNAL=18.
# We re-derive the default rather than import the kernel constant
# because the collector must run even in an environment where the
# kernel is mocked or partially overridden (synthetic K4Bench mode).
_DEFAULT_SIGNAL_THRESHOLD = 18


# Sentinel strings for rejection causes. Kept short + stable so report
# consumers can grep / branch on them. Adding a new cause requires
# bumping SCHEMA_VERSION.
REJECTION_CAUSE_NEVER_EMITTED = "obligation_not_emitted"
REJECTION_CAUSE_CRITIC_REJECTED = "emitted_but_critic_rejected"
REJECTION_CAUSE_ADMISSIBILITY_REJECTED = "emitted_but_admissibility_rejected"
REJECTION_CAUSE_EXHAUSTION_OVERLAP = "emitted_but_exhaustion_overlap"
REJECTION_CAUSE_TESTED_NO_SIGNAL = "tested_but_no_signal"
# Distinct from ADMISSIBILITY_REJECTED: the spec matched the obligation
# but no dispatcher outcome was recorded at all (dry-run, controller halt
# before dispatch, etc.). PR 2 may further refine; PR 1 keeps the
# distinction explicit so a dry-run smoke does not get reported as an
# admissibility failure that didn't actually happen.
REJECTION_CAUSE_HALTED_BEFORE_DISPATCH = "halted_before_dispatch"
REJECTION_CAUSE_SATISFIED = "satisfied"
# v2: the obligation's matching spec was emitted AND passed the
# dispatcher's admissibility/translation gate, but execution was
# intentionally skipped (coverage scheduler, Approach A). Counts as
# SATISFIED. Distinct from REJECTION_CAUSE_HALTED_BEFORE_DISPATCH, which
# is an "ok"-but-no-marker dry-run/halt with no admissibility_only flag.
REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE = "emitted_and_admissible"


# Causes that count as the obligation being closed. Referenced by both
# _aggregate_pass (the `passed` boolean) and build_report
# (obligations_satisfied / closure_rate) — keep them on one definition so
# a future satisfying cause can't be added to one site and missed at the other.
_SATISFYING_CAUSES: frozenset[str] = frozenset({
    REJECTION_CAUSE_SATISFIED,
    REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE,
})


# ─── Event records (one-shot, append-only) ───────────────────────────────────


@dataclass
class EmittedSpecRecord:
    """A single ``HypothesisSpec`` that the theorist (or fallback) emitted.

    Recorded once per theory, BEFORE the critic runs. Captures the
    layer-and-param structure the collector needs to test obligations
    against, plus the hypothesis_id that ties it to downstream critic /
    dispatcher events.
    """
    hypothesis_id: str
    title: str
    family: str
    spec_hash: str = ""
    # Each layer's flattened parameters: [{"kind": str, "variant": opt str,
    # "alphabet": str, "params": dict[str, Any]}, ...]. The "params" dict
    # preserves enumerated-value lists from ParamRange.values (we DON'T
    # collapse to scalars), so an obligation matcher can do membership
    # tests for "SERPENTINE in period_keyword.values".
    layers: list[dict[str, Any]] = field(default_factory=list)
    origin: str = "theorist_agent"     # mirrors TheoryRecord.origin
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "title": self.title,
            "family": self.family,
            "spec_hash": self.spec_hash,
            "layers": list(self.layers),
            "origin": self.origin,
            "recorded_at": self.recorded_at,
        }


@dataclass
class CriticOutcomeRecord:
    hypothesis_id: str
    decision: str                      # CriticDecision.value
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "decision": self.decision,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "recorded_at": self.recorded_at,
        }


@dataclass
class RedTeamOutcomeRecord:
    hypothesis_id: str
    verdict: str
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "recorded_at": self.recorded_at,
        }


@dataclass
class DispatcherOutcomeRecord:
    """The dispatcher's verdict on one ``HypothesisSpec``.

    ``admissibility_verdict`` is one of ``"ok"``, ``"rejected"``,
    ``"error"``. The dispatcher's own ``JobResult.admissibility_verdict``
    string can be passed through verbatim. ``admissibility_reasons``
    preserves the explicit reason list so the report can tell apart
    "exhaustion overlap" from "translation gap" from "budget exceeded".
    """
    hypothesis_id: str
    spec_hash: str
    admissibility_verdict: str
    admissibility_reasons: list[str] = field(default_factory=list)
    is_exhaustion_overlap: bool = False
    total_tested: int = 0
    best_score: float = 0.0
    best_p_value_vs_null: Optional[float] = None
    universe_hash: str = ""
    signal_alert: bool = False
    breakthrough_alert: bool = False
    admissibility_only: bool = False
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "spec_hash": self.spec_hash,
            "admissibility_verdict": self.admissibility_verdict,
            "admissibility_reasons": list(self.admissibility_reasons),
            "is_exhaustion_overlap": self.is_exhaustion_overlap,
            "total_tested": self.total_tested,
            "best_score": self.best_score,
            "best_p_value_vs_null": self.best_p_value_vs_null,
            "universe_hash": self.universe_hash,
            "signal_alert": self.signal_alert,
            "breakthrough_alert": self.breakthrough_alert,
            "admissibility_only": self.admissibility_only,
            "recorded_at": self.recorded_at,
        }


# ─── Helpers ────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _layer_to_record(layer: Any) -> dict[str, Any]:
    """Flatten a CipherLayer (or its to_dict form) into a recording.

    Pulls the layer's ``params`` ParamRange list into a flat dict from
    parameter name → enumerated value list (the original
    ``ParamRange.values`` list or, for start/stop ranges, the
    ``list(range(start, stop))`` materialization). Preserves the
    ``variant`` parameter as a top-level field so obligation matching
    can pin it without re-reading params.

    Accepts both a live ``CipherLayer`` dataclass and its dict form.
    """
    # Resolve to dict form to keep the code single-pathed.
    if hasattr(layer, "to_dict"):
        d = layer.to_dict()
    elif isinstance(layer, dict):
        d = dict(layer)
    else:
        return {
            "kind": "<unknown>",
            "variant": None,
            "alphabet": "AZ",
            "params": {},
            "_warning": f"unrecognized layer object: {type(layer).__name__}",
        }
    kind = d.get("kind", "")
    alphabet = d.get("alphabet", "AZ")
    params_raw = d.get("params", []) or []
    flat_params: dict[str, Any] = {}
    variant: Optional[str] = None
    for p in params_raw:
        # ParamRange dict form: {"name": str, "values": list, "start": int, "stop": int, ...}
        if not isinstance(p, dict):
            # Shouldn't happen if upstream dumped via to_dict, but be defensive.
            continue
        name = p.get("name", "")
        if not name:
            continue
        values = p.get("values") or []
        start = p.get("start")
        stop = p.get("stop")
        if values:
            flat_params[name] = list(values)
        elif start is not None and stop is not None:
            try:
                flat_params[name] = list(range(int(start), int(stop)))
            except (TypeError, ValueError):
                flat_params[name] = []
        else:
            flat_params[name] = None
        # Promote 'variant' to a top-level surface for the obligation
        # matcher. Many DSL layers (quagmire, polybius, route) carry
        # variant on a ParamRange named "variant"; lifting it here means
        # the obligation matcher does not need to special-case the
        # parameter axis.
        if name == "variant":
            v_list = flat_params[name]
            if isinstance(v_list, list) and len(v_list) == 1:
                variant = v_list[0]
            elif isinstance(v_list, list):
                # variant range with multiple values — keep them in params
                # but leave the top-level variant unset.
                variant = None
            else:
                variant = v_list
    return {
        "kind": kind,
        "variant": variant,
        "alphabet": alphabet,
        "params": flat_params,
    }


def _spec_satisfies_obligation(
    spec_record: EmittedSpecRecord,
    obligation: ParameterObligation,
) -> bool:
    """True iff at least one layer in the spec satisfies the obligation."""
    for layer in spec_record.layers:
        kind = layer.get("kind", "")
        variant = layer.get("variant")
        params = layer.get("params", {}) or {}
        if obligation.matches(
            layer_kind=kind, layer_variant=variant, params=params,
        ):
            return True
    return False


# ─── Collector + report ─────────────────────────────────────────────────────


@dataclass
class CoverageAuditCollector:
    """Live per-run collector.

    Methods are named ``record_*`` so the controller's calling sites
    self-document. Every method swallows internal errors and logs them
    rather than raising — a broken collector callback must not crash a
    cycle.
    """

    profile: SyntheticProfile
    synthetic_mode: bool = True
    ledger_db_path: str = ""
    signal_threshold: int = _DEFAULT_SIGNAL_THRESHOLD

    run_started_at: str = field(default_factory=_now_iso)
    run_finished_at: str = ""

    emitted_specs: list[EmittedSpecRecord] = field(default_factory=list)
    critic_outcomes: list[CriticOutcomeRecord] = field(default_factory=list)
    redteam_outcomes: list[RedTeamOutcomeRecord] = field(default_factory=list)
    dispatcher_outcomes: list[DispatcherOutcomeRecord] = field(default_factory=list)

    extra_notes: list[str] = field(default_factory=list)

    # ── record_* methods (single chokepoint per event) ──────────────

    def record_emitted_spec(
        self,
        *,
        hypothesis_id: str,
        title: str,
        family: str,
        spec_hash: str = "",
        layers: Optional[list[Any]] = None,
        origin: str = "theorist_agent",
    ) -> None:
        try:
            layer_records = [_layer_to_record(layer) for layer in (layers or [])]
            self.emitted_specs.append(
                EmittedSpecRecord(
                    hypothesis_id=hypothesis_id,
                    title=title,
                    family=family,
                    spec_hash=spec_hash,
                    layers=layer_records,
                    origin=origin,
                    recorded_at=_now_iso(),
                )
            )
        except Exception:
            logger.exception("record_emitted_spec failed; continuing")

    def record_critic_outcome(
        self,
        *,
        hypothesis_id: str,
        decision: str,
        confidence: float = 0.0,
        reasons: Optional[list[str]] = None,
    ) -> None:
        try:
            self.critic_outcomes.append(
                CriticOutcomeRecord(
                    hypothesis_id=hypothesis_id,
                    decision=decision,
                    confidence=float(confidence),
                    reasons=list(reasons or []),
                    recorded_at=_now_iso(),
                )
            )
        except Exception:
            logger.exception("record_critic_outcome failed; continuing")

    def record_redteam_outcome(
        self,
        *,
        hypothesis_id: str,
        verdict: str,
        confidence: float = 0.0,
        reasons: Optional[list[str]] = None,
    ) -> None:
        try:
            self.redteam_outcomes.append(
                RedTeamOutcomeRecord(
                    hypothesis_id=hypothesis_id,
                    verdict=verdict,
                    confidence=float(confidence),
                    reasons=list(reasons or []),
                    recorded_at=_now_iso(),
                )
            )
        except Exception:
            logger.exception("record_redteam_outcome failed; continuing")

    def record_dispatcher_outcome(
        self,
        *,
        hypothesis_id: str,
        spec_hash: str = "",
        admissibility_verdict: str,
        admissibility_reasons: Optional[list[str]] = None,
        total_tested: int = 0,
        best_score: float = 0.0,
        best_p_value_vs_null: Optional[float] = None,
        universe_hash: str = "",
        signal_alert: bool = False,
        breakthrough_alert: bool = False,
        admissibility_only: bool = False,
    ) -> None:
        try:
            reasons = list(admissibility_reasons or [])
            is_overlap = any(
                "exhaustion overlap" in r.lower() for r in reasons
            )
            self.dispatcher_outcomes.append(
                DispatcherOutcomeRecord(
                    hypothesis_id=hypothesis_id,
                    spec_hash=spec_hash,
                    admissibility_verdict=admissibility_verdict,
                    admissibility_reasons=reasons,
                    is_exhaustion_overlap=is_overlap,
                    total_tested=int(total_tested),
                    best_score=float(best_score),
                    best_p_value_vs_null=best_p_value_vs_null,
                    universe_hash=universe_hash,
                    signal_alert=bool(signal_alert),
                    breakthrough_alert=bool(breakthrough_alert),
                    admissibility_only=bool(admissibility_only),
                    recorded_at=_now_iso(),
                )
            )
        except Exception:
            logger.exception("record_dispatcher_outcome failed; continuing")

    def add_note(self, note: str) -> None:
        try:
            self.extra_notes.append(str(note))
        except Exception:
            logger.exception("add_note failed; continuing")

    # ── obligation analysis ─────────────────────────────────────────

    def _critic_decision_for(self, hypothesis_id: str) -> Optional[str]:
        for c in self.critic_outcomes:
            if c.hypothesis_id == hypothesis_id:
                return c.decision
        return None

    def _dispatcher_outcome_for(
        self, hypothesis_id: str,
    ) -> Optional[DispatcherOutcomeRecord]:
        for d in self.dispatcher_outcomes:
            if d.hypothesis_id == hypothesis_id:
                return d
        return None

    def _evaluate_obligation(
        self, obligation: ParameterObligation,
    ) -> dict[str, Any]:
        """Compute the per-obligation diagnostic snapshot.

        Returns a dict with keys:
          - matching_spec_ids: list[str]
          - cause: one of REJECTION_CAUSE_* sentinels
          - cause_detail: human-readable explanation
          - tested_count: int (count of matching specs that actually ran)
        """
        matching: list[EmittedSpecRecord] = [
            s for s in self.emitted_specs
            if _spec_satisfies_obligation(s, obligation)
        ]
        matching_ids = [s.hypothesis_id for s in matching]

        if not matching:
            return {
                "matching_spec_ids": [],
                "cause": REJECTION_CAUSE_NEVER_EMITTED,
                "cause_detail": (
                    f"expected obligation not emitted: {obligation.describe()}"
                ),
                "tested_count": 0,
            }

        # At least one spec matched the obligation structurally. Walk
        # the downstream lifecycle.
        critic_rejected_all = True
        critic_decisions: list[str] = []
        for sid in matching_ids:
            decision = self._critic_decision_for(sid)
            if decision is None:
                # Critic hasn't been run for this spec — treat as
                # "not yet rejected" so we fall through to dispatcher.
                critic_rejected_all = False
            else:
                critic_decisions.append(decision)
                if decision == "approve":
                    critic_rejected_all = False
        if critic_rejected_all and critic_decisions:
            return {
                "matching_spec_ids": matching_ids,
                "cause": REJECTION_CAUSE_CRITIC_REJECTED,
                "cause_detail": (
                    f"obligation matched {len(matching_ids)} emitted "
                    f"spec(s) but the critic rejected every one of them "
                    f"({sorted(set(critic_decisions))})"
                ),
                "tested_count": 0,
            }

        # Check dispatcher outcomes.
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

        if any_tested:
            if best_score_seen >= self.signal_threshold:
                return {
                    "matching_spec_ids": matching_ids,
                    "cause": REJECTION_CAUSE_SATISFIED,
                    "cause_detail": (
                        f"obligation matched and dispatched specs "
                        f"reached best_score={best_score_seen:.1f} "
                        f">= signal_threshold {self.signal_threshold}"
                    ),
                    "tested_count": 1,
                }
            return {
                "matching_spec_ids": matching_ids,
                "cause": REJECTION_CAUSE_TESTED_NO_SIGNAL,
                "cause_detail": (
                    f"obligation matched and dispatched, best_score="
                    f"{best_score_seen:.1f} below signal_threshold "
                    f"{self.signal_threshold}"
                ),
                "tested_count": 1,
            }

        # Any single satisfying outcome on any matching spec closes the
        # obligation (mirrors how any_tested wins over sibling rejections).
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

        if any_exhaustion_overlap:
            return {
                "matching_spec_ids": matching_ids,
                "cause": REJECTION_CAUSE_EXHAUSTION_OVERLAP,
                "cause_detail": (
                    f"obligation matched but every dispatched spec was "
                    f"rejected by exhaustion-overlap admissibility "
                    f"(unexpected in synthetic mode — consider "
                    f"override_exhaustion=True or check bench_mode wiring)"
                ),
                "tested_count": 0,
            }
        if any_rejected_admissibility:
            return {
                "matching_spec_ids": matching_ids,
                "cause": REJECTION_CAUSE_ADMISSIBILITY_REJECTED,
                "cause_detail": (
                    f"obligation matched but every dispatched spec was "
                    f"rejected at admissibility (translation gap, budget "
                    f"exceeded, or structural)"
                ),
                "tested_count": 0,
            }

        # Survived critic, no dispatcher record at all: dry-run or halt.
        return {
            "matching_spec_ids": matching_ids,
            "cause": REJECTION_CAUSE_HALTED_BEFORE_DISPATCH,
            "cause_detail": (
                "obligation matched and was emitted, but no dispatcher "
                "outcome was recorded (likely dry-run or cycle halted "
                "before dispatch)"
            ),
            "tested_count": 0,
        }

    def _aggregate_pass(self) -> tuple[bool, list[str]]:
        """Determine pass/fail and accumulate fail_reasons.

        For PR 1, "pass" requires every obligation to have at least
        ``minimum_expected_dispatch`` matching specs that reached the
        kernel and produced best_score >= signal_threshold. Lower bars
        (e.g. "matched + dispatched but no signal") count as PARTIAL
        progress for reporting but still FAIL the profile pass
        condition. PR 2 may relax this if a profile explicitly carries
        a lower pass bar.
        """
        if not self.profile.obligations:
            # Blocked profile shouldn't have reached this code path,
            # but guard anyway.
            return (False, [f"profile {self.profile.profile_id!r} has no obligations"])
        fail_reasons: list[str] = []
        for ob in self.profile.obligations:
            diag = self._evaluate_obligation(ob)
            if diag["cause"] not in _SATISFYING_CAUSES:
                fail_reasons.append(diag["cause_detail"])
        return (not fail_reasons, fail_reasons)

    # ── public report assembly ──────────────────────────────────────

    def build_report(self) -> "CoverageReport":
        if not self.run_finished_at:
            self.run_finished_at = _now_iso()
        passed, fail_reasons = self._aggregate_pass()
        per_obligation = [
            {
                "obligation": ob.describe(),
                "expected_family": ob.expected_family,
                "expected_layer_kind": ob.expected_layer_kind,
                "expected_layer_variant": ob.expected_layer_variant,
                "expected_parameter_axis": ob.expected_parameter_axis,
                "expected_parameter_value": ob.expected_parameter_value,
                "minimum_expected_dispatch": ob.minimum_expected_dispatch,
                **self._evaluate_obligation(ob),
            }
            for ob in self.profile.obligations
        ]
        tested_specs = [
            d for d in self.dispatcher_outcomes
            if d.admissibility_verdict.lower().startswith("ok")
            and d.total_tested > 0
        ]
        admissibility_rejections = [
            d for d in self.dispatcher_outcomes
            if not d.admissibility_verdict.lower().startswith("ok")
        ]
        exhaustion_overlap_rejections = [
            d for d in admissibility_rejections if d.is_exhaustion_overlap
        ]
        best_score = max(
            (d.best_score for d in self.dispatcher_outcomes), default=0.0,
        )
        best_p = None
        for d in self.dispatcher_outcomes:
            if d.best_p_value_vs_null is not None:
                if best_p is None or d.best_p_value_vs_null < best_p:
                    best_p = d.best_p_value_vs_null
        signal_alerts = [
            d.hypothesis_id for d in self.dispatcher_outcomes if d.signal_alert
        ]
        breakthrough_alerts = [
            d.hypothesis_id for d in self.dispatcher_outcomes
            if d.breakthrough_alert
        ]
        obligations_total = len(self.profile.obligations)
        obligations_satisfied = sum(
            1 for o in per_obligation
            if o["cause"] in _SATISFYING_CAUSES
        )
        closure_rate = (
            obligations_satisfied / obligations_total
            if obligations_total > 0 else 0.0
        )
        missing_obligations = [
            o["obligation"] for o in per_obligation
            if o["cause"] == REJECTION_CAUSE_NEVER_EMITTED
        ]
        counts = {
            "obligations_total": obligations_total,
            "obligations_satisfied": obligations_satisfied,
            "specs_emitted": len(self.emitted_specs),
            "specs_critic_approved": sum(
                1 for c in self.critic_outcomes if c.decision == "approve"
            ),
            "specs_critic_rejected": sum(
                1 for c in self.critic_outcomes if c.decision != "approve"
            ),
            "specs_dispatched": len(self.dispatcher_outcomes),
            "specs_rejected_admissibility": len(admissibility_rejections),
            "specs_rejected_exhaustion_overlap": len(exhaustion_overlap_rejections),
            "specs_tested": len(tested_specs),
            "obligation_closure_rate": closure_rate,
        }
        return CoverageReport(
            schema_version=SCHEMA_VERSION,
            profile_id=self.profile.profile_id,
            profile_description=self.profile.description,
            profile_status=self.profile.status,
            profile_blocked_reason=self.profile.blocked_reason,
            profile_pass_condition_summary=self.profile.pass_condition_summary(),
            synthetic_mode=self.synthetic_mode,
            ledger_db_path=self.ledger_db_path,
            run_started_at=self.run_started_at,
            run_finished_at=self.run_finished_at,
            expected_obligations=[ob.describe() for ob in self.profile.obligations],
            per_obligation=per_obligation,
            emitted_specs=[s.to_dict() for s in self.emitted_specs],
            critic_outcomes=[c.to_dict() for c in self.critic_outcomes],
            redteam_outcomes=[r.to_dict() for r in self.redteam_outcomes],
            dispatcher_outcomes=[d.to_dict() for d in self.dispatcher_outcomes],
            admissibility_rejections=[d.to_dict() for d in admissibility_rejections],
            exhaustion_overlap_rejections=[
                d.to_dict() for d in exhaustion_overlap_rejections
            ],
            tested_specs=[d.to_dict() for d in tested_specs],
            matched_expected_obligation=(closure_rate == 1.0),
            missing_expected_obligations=missing_obligations,
            best_score=best_score,
            best_p_value_vs_null=best_p,
            signal_alerts=signal_alerts,
            breakthrough_alerts=breakthrough_alerts,
            passed=passed,
            fail_reasons=fail_reasons,
            counts=counts,
            extra_notes=list(self.extra_notes),
        )

    def write_report(self, path: Path) -> Path:
        """Build the report and write it to ``path`` (atomic write).

        Returns the resolved path. Always writes — even if ``passed``
        is False — because failing-to-emit is the T1 postmortem failure
        mode this module exists to prevent.
        """
        report = self.build_report()
        return write_report(report, path)


@dataclass
class CoverageReport:
    """Frozen view of a CoverageAuditCollector at end-of-run.

    Schema versioning: bump ``schema_version`` whenever a field is
    added, renamed, or removed. Consumers (CI dashboards, postmortem
    scripts) key off ``schema_version`` to pick a parser.
    """
    schema_version: str
    profile_id: str
    profile_description: str
    profile_status: str
    profile_blocked_reason: str
    profile_pass_condition_summary: str
    synthetic_mode: bool
    ledger_db_path: str
    run_started_at: str
    run_finished_at: str
    expected_obligations: list[str]
    per_obligation: list[dict[str, Any]]
    emitted_specs: list[dict[str, Any]]
    critic_outcomes: list[dict[str, Any]]
    redteam_outcomes: list[dict[str, Any]]
    dispatcher_outcomes: list[dict[str, Any]]
    admissibility_rejections: list[dict[str, Any]]
    exhaustion_overlap_rejections: list[dict[str, Any]]
    tested_specs: list[dict[str, Any]]
    matched_expected_obligation: bool
    missing_expected_obligations: list[str]
    best_score: float
    best_p_value_vs_null: Optional[float]
    signal_alerts: list[str]
    breakthrough_alerts: list[str]
    passed: bool
    fail_reasons: list[str]
    counts: dict[str, Any]
    extra_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "profile_description": self.profile_description,
            "profile_status": self.profile_status,
            "profile_blocked_reason": self.profile_blocked_reason,
            "profile_pass_condition_summary": self.profile_pass_condition_summary,
            "synthetic_mode": self.synthetic_mode,
            "ledger_db_path": self.ledger_db_path,
            "run_started_at": self.run_started_at,
            "run_finished_at": self.run_finished_at,
            "expected_obligations": list(self.expected_obligations),
            "per_obligation": list(self.per_obligation),
            "emitted_specs": list(self.emitted_specs),
            "critic_outcomes": list(self.critic_outcomes),
            "redteam_outcomes": list(self.redteam_outcomes),
            "dispatcher_outcomes": list(self.dispatcher_outcomes),
            "admissibility_rejections": list(self.admissibility_rejections),
            "exhaustion_overlap_rejections": list(self.exhaustion_overlap_rejections),
            "tested_specs": list(self.tested_specs),
            "matched_expected_obligation": self.matched_expected_obligation,
            "missing_expected_obligations": list(self.missing_expected_obligations),
            "best_score": self.best_score,
            "best_p_value_vs_null": self.best_p_value_vs_null,
            "signal_alerts": list(self.signal_alerts),
            "breakthrough_alerts": list(self.breakthrough_alerts),
            "pass": self.passed,  # JSON key is "pass" (operator-friendly)
            "fail_reasons": list(self.fail_reasons),
            "counts": dict(self.counts),
            "extra_notes": list(self.extra_notes),
        }


# ─── Path resolution + atomic write ──────────────────────────────────────────


def resolve_report_path(
    *,
    profile_id: str,
    coverage_report_arg: Optional[str],
    project_root: Path,
) -> Path:
    """Decide the on-disk path for the coverage report.

    Conventions:
      - If ``coverage_report_arg`` is None, default to
        ``<project_root>/results/coverage_reports/
         <UTC timestamp>_<profile_id>_coverage_report.json``.
      - If the arg points to a directory (existing OR ending in ``/``),
        treat as a directory and stamp the filename inside.
      - Otherwise treat the arg as a full file path.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    default_filename = f"{ts}_{profile_id}_coverage_report.json"
    if coverage_report_arg is None:
        target_dir = project_root / "results" / "coverage_reports"
        return target_dir / default_filename
    candidate = Path(coverage_report_arg)
    if not candidate.is_absolute():
        candidate = (project_root / candidate).resolve()
    # Directory iff the path explicitly ends with a separator OR is an
    # existing directory OR has no suffix at all (treat as a dir).
    looks_like_dir = (
        coverage_report_arg.endswith(os.sep)
        or coverage_report_arg.endswith("/")
        or candidate.is_dir()
        or (candidate.suffix == "" and not candidate.exists())
    )
    if looks_like_dir:
        return candidate / default_filename
    return candidate


def write_report(report: CoverageReport, path: Path) -> Path:
    """Atomically write ``report`` to ``path`` as pretty JSON.

    Atomic via tmp-file + rename so a crash mid-write never leaves a
    half-written report on disk (the artifact is the single observable
    output, so partial writes would be worse than a missing file).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    payload = json.dumps(report.to_dict(), sort_keys=True, indent=2)
    tmp.write_text(payload)
    os.replace(tmp, path)
    return path


# ─── Convenience: build collector from a profile_id ─────────────────────────


def build_collector_for_profile(
    profile_id: str,
    *,
    synthetic_mode: bool = True,
    ledger_db_path: str = "",
    signal_threshold: int = _DEFAULT_SIGNAL_THRESHOLD,
) -> CoverageAuditCollector:
    """Look up a profile and instantiate a fresh collector for it."""
    profile = get_profile(profile_id)
    return CoverageAuditCollector(
        profile=profile,
        synthetic_mode=synthetic_mode,
        ledger_db_path=ledger_db_path,
        signal_threshold=signal_threshold,
    )


__all__ = [
    "SCHEMA_VERSION",
    "REJECTION_CAUSE_NEVER_EMITTED",
    "REJECTION_CAUSE_CRITIC_REJECTED",
    "REJECTION_CAUSE_ADMISSIBILITY_REJECTED",
    "REJECTION_CAUSE_EXHAUSTION_OVERLAP",
    "REJECTION_CAUSE_TESTED_NO_SIGNAL",
    "REJECTION_CAUSE_HALTED_BEFORE_DISPATCH",
    "REJECTION_CAUSE_SATISFIED",
    "REJECTION_CAUSE_EMITTED_AND_ADMISSIBLE",
    "CoverageAuditCollector",
    "CoverageReport",
    "EmittedSpecRecord",
    "CriticOutcomeRecord",
    "RedTeamOutcomeRecord",
    "DispatcherOutcomeRecord",
    "build_collector_for_profile",
    "resolve_report_path",
    "write_report",
]
