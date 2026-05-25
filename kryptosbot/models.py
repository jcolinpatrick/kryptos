"""
Structured data models for the KryptosBot research controller.

All inter-component communication uses these typed contracts.
Free-text reasoning is allowed in human-facing summaries but never
drives controller logic.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ContractValidationError(Exception):
    """Raised when a structured contract fails strict validation."""
    pass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TheoryStatus(str, Enum):
    """Lifecycle states for a theory in the ledger."""
    PROPOSED = "proposed"          # newly generated, not yet criticized
    CRITICIZED = "criticized"      # critic has reviewed; awaiting dispatch decision
    APPROVED = "approved"          # passed critic, queued for testing
    RUNNING = "running"            # experiment in progress
    COMPLETED = "completed"        # experiment finished, outcome recorded
    ELIMINATED = "eliminated"      # conclusively disproved
    PROMISING = "promising"        # partial signal, warrants follow-up
    ERROR = "error"                # worker errored / transport failed; not a real test
    SUPERSEDED = "superseded"      # replaced by a more refined theory
    WITHDRAWN = "withdrawn"        # manually removed from consideration


class CriticDecision(str, Enum):
    """Critic stage outcomes."""
    APPROVE = "approve"            # novel, well-constrained, worth testing
    REJECT_DUPLICATE = "reject_duplicate"
    REJECT_ELIMINATED = "reject_eliminated"
    REJECT_EMPIRICALLY_DEAD = "reject_empirically_dead"  # NEW: yield-feedback Phase 1
    REJECT_UNDERCONSTRAINED = "reject_underconstrained"
    REJECT_LOW_INFORMATION = "reject_low_information"
    REJECT_CONTRADICTED = "reject_contradicted"
    DEFER = "defer"                # needs more information before decision


class WorkerStatus(str, Enum):
    """Worker execution outcomes."""
    SUCCESS = "success"
    DISPROVED = "disproved"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    TIMEOUT = "timeout"
    # R3-2 (2026-04-21): dispatcher rejected the spec before any compute
    # ran — admissibility failed (translation gap, cardinality > budget,
    # exhaustion overlap without override, or procedural expansion error).
    # Distinct from INCONCLUSIVE (ran but nothing stored) and ERROR
    # (ran and raised). See DSL_CUTOVER_CONTRACT §4.2 for semantics.
    REJECTED_ADMISSIBILITY = "rejected_admissibility"


class EvidenceType(str, Enum):
    """Types of evidence that can be linked to a theory."""
    EXPERIMENT_RESULT = "experiment_result"
    CRIB_MATCH = "crib_match"
    BEAN_CONSTRAINT = "bean_constraint"
    STATISTICAL_TEST = "statistical_test"
    DISPROOF = "disproof"
    HISTORICAL_PRECEDENT = "historical_precedent"
    ANOMALY_LINK = "anomaly_link"
    CROSS_REFERENCE = "cross_reference"


class FamilyStatus(str, Enum):
    """Status of a theory family in the research landscape."""
    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    PARTIALLY_EXPLORED = "partially_explored"
    BLOCKED = "blocked"            # awaiting audit resolution
    RETIRED = "retired"


class AnomalyStatus(str, Enum):
    """Status of a tracked anomaly."""
    OPEN = "open"
    EXPLAINED = "explained"
    DISPUTED = "disputed"
    IRRELEVANT = "irrelevant"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(core_claim: str, mechanism: str, family: str) -> str:
    """Deterministic 12-char hex ID from the defining properties of a theory."""
    h = hashlib.sha256(f"{core_claim}|{mechanism}|{family}".encode()).hexdigest()
    return h[:12]


@dataclass
class TheoryRecord:
    """
    A single hypothesis in the theory ledger.

    This is the primary unit of structured research state. Every field
    is machine-readable; narrative summaries exist only for human review.
    """
    # Identity
    hypothesis_id: str = ""
    title: str = ""
    core_claim: str = ""
    mechanism: str = ""

    # Classification
    family: str = ""
    subfamily: str = ""
    tags: list[str] = field(default_factory=list)

    # Research context
    clue_anchors_used: list[str] = field(default_factory=list)
    anomalies_exploited: list[str] = field(default_factory=list)
    novelty_basis: str = ""
    prior_related_hypotheses: list[str] = field(default_factory=list)

    # Test specification
    minimal_test_spec: dict[str, Any] = field(default_factory=dict)
    kill_criteria: list[str] = field(default_factory=list)
    expected_signal: str = ""
    compute_cost_estimate: str = ""
    # Day 5: structured cost estimate for compute-budget-aware critic
    # decisions. Theorist emits this; critic can use it to prioritize cheap
    # kills first and gate expensive long-shots. 0 = unspecified.
    estimated_compute_minutes: int = 0

    # Lifecycle
    status: TheoryStatus = TheoryStatus.PROPOSED
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    # Critic stage
    critic_verdict: Optional[CriticVerdict] = None

    # Experiment linkage
    experiment_ids: list[str] = field(default_factory=list)

    # Outcome
    outcome_summary: str = ""
    failure_reason: str = ""
    best_score: float = 0.0
    best_plaintext: str = ""

    # Meta
    generalization_strength: str = ""
    notes: str = ""

    # R2-3 (2026-04-21): exhaustion-overlap override justification. When
    # the theory's minimal_test_spec carries override_exhaustion=True,
    # this field stores the justification verbatim so the critic can
    # detect duplicate-justification laundering across theories.
    # Default "" means no override was claimed.
    override_justification: str = ""

    # R3-2 (2026-04-21): DSL spec attached by the theorist for
    # Category-A (cipher-family) theories. A dict conforming to
    # HypothesisSpec.to_dict() shape enables DSL dispatch via
    # job_dispatcher.execute(). Empty dict means "no spec attached" —
    # appropriate for Category B (family in NON_DSL_FAMILIES) where
    # the theory routes to _run_worker_legacy. Category C (cipher-
    # family with empty/malformed spec) is rejected by the critic.
    # See DSL_CUTOVER_CONTRACT §5.
    dsl_spec: dict[str, Any] = field(default_factory=dict)

    # Campaign-A hardening (2026-04-22): where this TheoryRecord
    # originated. Red-team finding: _programmatic_fallback previously
    # emitted TheoryRecords indistinguishable from theorist output
    # except by title-pattern grep on "Explore X family". That post-hoc
    # detection is insufficient to tell a healthy cycle from a sustained
    # silent fallback. ``origin`` is the durable tag so mortality tables
    # and halt-condition counters can see fallback theories explicitly.
    #
    # Allowed values:
    #   "theorist_agent"          — default; parsed from a real
    #                               theorist agent response
    #   "programmatic_fallback"   — generated by
    #                               ResearchController._programmatic_fallback
    #                               because the theorist path failed
    #                               or returned no parseable proposals
    origin: str = "theorist_agent"

    def __post_init__(self) -> None:
        if not self.hypothesis_id and self.core_claim:
            self.hypothesis_id = _stable_id(
                self.core_claim, self.mechanism, self.family
            )

    def touch(self) -> None:
        """Update the updated_at timestamp."""
        self.updated_at = _now_iso()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        if self.critic_verdict:
            d["critic_verdict"] = self.critic_verdict.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TheoryRecord:
        d = dict(d)  # don't mutate caller's dict
        if "status" in d and isinstance(d["status"], str):
            d["status"] = TheoryStatus(d["status"])
        cv = d.pop("critic_verdict", None)
        rec = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        if cv and isinstance(cv, dict):
            rec.critic_verdict = CriticVerdict.from_dict(cv)
        return rec


@dataclass
class EmpiricalDeathRejectionPayload:
    """Structured payload attached to REJECT_EMPIRICALLY_DEAD verdicts.

    Phase 1 emitted suggested_mechanisms: tuple[str, ...] = (). Phase 2
    renames and widens to suggested_mechanism_records: tuple[
    CipherDiscoverySuggestion, ...] and populates from the cipher-discovery
    KB at REJECT_EMPIRICALLY_DEAD time. See
    docs/specs/2026-05-16-yield-feedback-phase2-design.md §4.3.
    """
    family: str
    # Optional only because from_dict may receive a malformed/legacy
    # row where the verdict block is empty. Production code paths
    # (critic gate Task 9) always populate this with a real verdict.
    verdict: Optional["FamilyYieldVerdict"] = None
    bypass_failed_reasons: tuple[str, ...] = ()
    # NEW Phase 2. Structured KB suggestion records, JSON-serializable
    # via CipherDiscoverySuggestion.to_dict / from_dict. Always () when
    # KB DB is missing or no candidate survives the novelty join.
    # Typed as bare `tuple` to avoid a circular import on
    # CipherDiscoverySuggestion (lives in kryptosbot.kb_injection, which
    # itself imports nothing from models).
    suggested_mechanism_records: tuple = ()
    suggestion_source: str = "none"  # "cipher_discovery_kb" | "none"
    suggestion_query_scope: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        # Avoid asdict() so we can serialize the suggestion records
        # through their own to_dict and avoid nested-dataclass round-trip
        # surprises.
        verdict_d: Optional[dict[str, Any]] = None
        if self.verdict is not None:
            # FamilyYieldVerdict is a frozen dataclass — asdict works.
            verdict_d = asdict(self.verdict)
        recs: list[dict[str, Any]] = []
        for rec in self.suggested_mechanism_records or ():
            if hasattr(rec, "to_dict"):
                recs.append(rec.to_dict())
            elif isinstance(rec, dict):
                recs.append(dict(rec))
            # else: silently skip — Phase-1 strings cannot round-trip
            #  through the Phase-2 typed reader anyway. The from_dict
            #  helper enforces this asymmetry on read.
        return {
            "family": self.family,
            "verdict": verdict_d,
            "bypass_failed_reasons": list(self.bypass_failed_reasons or ()),
            "suggested_mechanism_records": recs,
            "suggestion_source": self.suggestion_source,
            "suggestion_query_scope": dict(self.suggestion_query_scope or {}),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EmpiricalDeathRejectionPayload:
        from kryptosbot.family_yield import FamilyYieldStats, FamilyYieldVerdict
        from kryptosbot.kb_injection import CipherDiscoverySuggestion

        d = dict(d)
        verdict_d = d.get("verdict") or {}
        stats_d = verdict_d.get("stats") or {}

        verdict: Optional[FamilyYieldVerdict] = None
        if verdict_d and stats_d:
            stats = FamilyYieldStats(**{
                k: stats_d.get(k) for k in (
                    "family", "trials", "mean_score", "best_score",
                    "promotions", "eliminated",
                )
            })
            verdict = FamilyYieldVerdict(
                family=verdict_d.get("family", ""),
                status=verdict_d.get("status", "healthy"),
                reasons=tuple(verdict_d.get("reasons") or ()),
                stats=stats,
            )

        # Read new key first; fall back to legacy key (Phase 1 emitted
        # an empty tuple of strings under "suggested_mechanisms").
        rec_payload = d.get("suggested_mechanism_records")
        if rec_payload is None:
            # Legacy key tolerated; non-record-shaped entries are dropped.
            legacy = d.get("suggested_mechanisms") or []
            rec_payload = [
                r for r in legacy if isinstance(r, dict)
            ]
        recs: list[CipherDiscoverySuggestion] = []
        for r in rec_payload or ():
            if isinstance(r, dict):
                try:
                    recs.append(CipherDiscoverySuggestion.from_dict(r))
                except Exception:
                    continue

        return cls(
            family=d.get("family", ""),
            verdict=verdict,
            bypass_failed_reasons=tuple(d.get("bypass_failed_reasons") or ()),
            suggested_mechanism_records=tuple(recs),
            suggestion_source=d.get("suggestion_source", "none"),
            suggestion_query_scope=dict(d.get("suggestion_query_scope") or {}),
        )


@dataclass
class CriticVerdict:
    """
    Structured output from the critic stage.

    Persisted alongside the theory so the controller can explain
    why a hypothesis was approved or rejected.
    """
    decision: CriticDecision = CriticDecision.DEFER
    confidence: float = 0.0          # 0.0-1.0
    reasons: list[str] = field(default_factory=list)
    similar_hypotheses: list[str] = field(default_factory=list)
    contradicting_facts: list[str] = field(default_factory=list)
    estimated_information_gain: str = ""
    reviewed_at: str = field(default_factory=_now_iso)
    # NEW (yield-feedback Phase 1). None for every decision other than
    # REJECT_EMPIRICALLY_DEAD. Backward-compat: absent on pre-Phase-1
    # ledger rows; from_dict treats absence as None.
    empirical_death: Optional["EmpiricalDeathRejectionPayload"] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        # Route empirical_death through its own to_dict so the Phase 2
        # CipherDiscoverySuggestion records serialize via their explicit
        # to_dict (frozen dataclass + tuple field — asdict's recursion
        # would still work for the fixture shape today, but the explicit
        # call avoids drift if either schema evolves).
        if self.empirical_death is None:
            d["empirical_death"] = None
        else:
            d["empirical_death"] = self.empirical_death.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CriticVerdict:
        d = dict(d)
        if "decision" in d and isinstance(d["decision"], str):
            d["decision"] = CriticDecision(d["decision"])
        ed = d.get("empirical_death")
        if ed is not None and isinstance(ed, dict):
            d["empirical_death"] = EmpiricalDeathRejectionPayload.from_dict(ed)
        # else: ed is None or missing; d already has None (or no key, which
        #       falls through to dataclass default via __dataclass_fields__
        #       filter below).
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class WorkerContract:
    """
    Strict JSON contract for worker output.

    Workers MUST produce this structure. Narrative summaries are optional
    and never parsed for control flow.
    """
    hypothesis_id: str = ""
    worker_role: str = ""              # e.g. "agent_sdk", "local_compute", "oracle"
    status: WorkerStatus = WorkerStatus.INCONCLUSIVE
    # score is a float MIRROR of crib_score after kernel verification —
    # NOT an aggregate score from kryptos.kernel.scoring.aggregate. The
    # name is preserved for ledger backward compatibility, but no
    # control-flow path consumes it as anything other than "crib_score
    # cast to float". See contracts._verify_against_kernel and the
    # comment at line ~126 in contracts.py for the rationale (alerts
    # gate on crib_score + bean_passed; a full ScoreBreakdown adds
    # coupling for no benefit). Worker-self-reported `score` is
    # discarded by the contract validator and replaced with this
    # mirrored value at boundary parse time.
    score: float = 0.0
    crib_score: int = 0
    bean_passed: bool = False
    best_plaintext: str = ""
    disproof_evidence: list[str] = field(default_factory=list)
    supporting_evidence: list[str] = field(default_factory=list)
    next_action: str = ""              # structured recommendation
    family_generalization: str = ""    # what this result implies for the family
    raw_artifacts: dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    error: str = ""

    # Optional narrative (not parsed by controller)
    narrative_summary: str = ""

    # Independent verification fields. Populated by contracts.py after the
    # worker's self-reported score fields are recomputed against the kernel.
    # NEVER trust crib_score / bean_passed / score without checking these.
    fields_overwritten: bool = False
    worker_self_report: dict[str, Any] = field(default_factory=dict)
    verification_error: str = ""
    # Which additive cipher variant produced the Bean PASS when
    # bean_passed is True. None when bean_passed is False or when
    # verification could not run. Valid values: "vigenere", "beaufort",
    # "variant_beaufort", None. Added in framework maturation Phase 3
    # (2026-04-21) so downstream auditing can distinguish which of the
    # three additive variants the kernel accepted — the variant matters
    # for interpreting the derived keystream, even though Bean validity
    # itself is variant-independent at correct cribs (see
    # kryptos.kernel.constraints.derive.derive_bean_constraints, which
    # superseded the deleted kryptos.kernel.constants._derive_bean_ineq).
    bean_variant: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> WorkerContract:
        """Lenient deserialization for reading stored data.

        Invalid enum values are replaced with INCONCLUSIVE and flagged
        in the error field. Use validated_from_dict for boundary parsing
        where invalid input must be rejected.
        """
        d = dict(d)
        if "status" in d and isinstance(d["status"], str):
            try:
                d["status"] = WorkerStatus(d["status"])
            except ValueError:
                original = d["status"]
                d["status"] = WorkerStatus.INCONCLUSIVE
                d.setdefault("error", "")
                d["error"] = (
                    f"[VALIDATION] Invalid status '{original}' replaced with INCONCLUSIVE. "
                    + d["error"]
                )
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @classmethod
    def validated_from_dict(cls, d: dict[str, Any]) -> WorkerContract:
        """Strict deserialization for boundary parsing.

        Raises ContractValidationError if required fields are missing
        or enum values are invalid. The controller must use this path
        for incoming worker output.
        """
        d = dict(d)
        errors: list[str] = []

        # Validate status
        status_val = d.get("status")
        if status_val is None:
            errors.append("Missing required field: 'status'")
        elif isinstance(status_val, str):
            try:
                d["status"] = WorkerStatus(status_val)
            except ValueError:
                errors.append(
                    f"Invalid status '{status_val}'; "
                    f"valid: {[s.value for s in WorkerStatus]}"
                )

        # Validate numeric fields
        for fld in ("score", "crib_score"):
            val = d.get(fld)
            if val is not None and not isinstance(val, (int, float)):
                errors.append(f"Field '{fld}' must be numeric, got {type(val).__name__}")

        # Validate boolean fields
        if "bean_passed" in d and not isinstance(d["bean_passed"], bool):
            errors.append(f"Field 'bean_passed' must be bool, got {type(d['bean_passed']).__name__}")

        if errors:
            raise ContractValidationError("; ".join(errors))

        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def is_actionable(self) -> bool:
        """Did this worker produce a result the controller should act on?"""
        return self.status in (WorkerStatus.SUCCESS, WorkerStatus.DISPROVED)


@dataclass
class ExperimentRecord:
    """Tracks a single experiment execution."""
    experiment_id: str = ""
    hypothesis_id: str = ""
    started_at: str = field(default_factory=_now_iso)
    completed_at: str = ""
    worker_role: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    result: Optional[WorkerContract] = None
    script_id: str = ""                # link to exhaustion_log entry if applicable

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.result:
            d["result"] = self.result.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ExperimentRecord:
        d = dict(d)
        result_data = d.pop("result", None)
        rec = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        if result_data and isinstance(result_data, dict):
            rec.result = WorkerContract.from_dict(result_data)
        return rec


@dataclass
class AnomalyRecord:
    """A tracked anomaly in the K4 research landscape."""
    anomaly_id: str = ""
    title: str = ""
    description: str = ""
    status: AnomalyStatus = AnomalyStatus.OPEN
    source: str = ""                   # where this anomaly was identified
    theories_exploring: list[str] = field(default_factory=list)
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AnomalyRecord:
        d = dict(d)
        if "status" in d and isinstance(d["status"], str):
            d["status"] = AnomalyStatus(d["status"])
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class FamilyRecord:
    """Status of a cipher/approach family in the research landscape."""
    family_id: str = ""
    name: str = ""
    description: str = ""
    status: FamilyStatus = FamilyStatus.ACTIVE
    subfamilies: list[str] = field(default_factory=list)
    total_theories: int = 0
    eliminated_theories: int = 0
    best_score: float = 0.0
    elimination_tier: int = 0          # 0=untested, 1=proven, 2=exhaustive, 3=partial, 4=bespoke
    elimination_evidence: str = ""
    notes: str = ""
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FamilyRecord:
        d = dict(d)
        if "status" in d and isinstance(d["status"], str):
            d["status"] = FamilyStatus(d["status"])
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class EvidenceLink:
    """Links a piece of evidence to a theory."""
    evidence_id: str = ""
    hypothesis_id: str = ""
    evidence_type: EvidenceType = EvidenceType.EXPERIMENT_RESULT
    content: str = ""
    experiment_id: str = ""
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence_type"] = self.evidence_type.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EvidenceLink:
        d = dict(d)
        if "evidence_type" in d and isinstance(d["evidence_type"], str):
            d["evidence_type"] = EvidenceType(d["evidence_type"])
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class ControllerState:
    """
    Snapshot of the controller's decision-making state.

    Persisted between controller cycles so the system can resume
    without re-reading everything.
    """
    cycle_number: int = 0
    last_cycle_at: str = ""
    theories_proposed: int = 0
    theories_tested: int = 0
    theories_eliminated: int = 0
    theories_promising: int = 0
    active_experiments: list[str] = field(default_factory=list)
    recent_outcomes: list[dict[str, Any]] = field(default_factory=list)
    underexplored_families: list[str] = field(default_factory=list)
    open_anomalies: list[str] = field(default_factory=list)
    theorist_parse_successes: int = 0
    theorist_parse_partial_successes: int = 0
    theorist_fallbacks: int = 0
    theorist_fallback_reasons: dict[str, int] = field(default_factory=dict)
    last_theorist_parse_diagnostics: dict[str, Any] = field(default_factory=dict)

    # Campaign-A hardening (2026-04-22): runtime halt counters. Red-team
    # finding: R3 protocol §5 listed halt conditions (3 consecutive
    # fallback cycles, 3 consecutive D-zero cycles, matched_null_miss on
    # BREAKTHROUGH) but none were wired into either cycle loop. Without
    # the counters, an overnight run could drift in a degraded state for
    # all 15 cycles and the operator would only discover it at
    # postmortem time.
    #
    # Reset-to-zero semantics: counters reset to 0 whenever a cycle
    # breaks the streak. Thresholds are module-level constants on
    # ResearchController. The halt itself is enacted by the cycle loop
    # (both controller.run and run_controller.do_run, per
    # feedback_dup_cycle_loop_trap).
    consecutive_fallback_cycles: int = 0
    consecutive_d_zero_cycles: int = 0
    # Populated by ResearchController._check_cycle_hardening_halts when a
    # halt condition trips. Non-empty string means "cycle loop should
    # break with this reason." Persisted across sessions so a resume
    # after halt starts clean only after operator acknowledgment.
    halt_reason_hardening: str = ""

    # Yield-feedback Phase 1 escape telemetry. See spec §6.2.
    escape_needed_streak: int = 0
    last_escape_status: str = "none"
    last_escape_families_blocked: list[str] = field(default_factory=list)
    last_escape_families_blocked_total: int = 0
    last_escape_cycle: int = 0
    last_partial_empirical_block_count: int = 0

    # NEW Phase 2: aggregated KB suggestions from the prior cycle's
    # REJECT_EMPIRICALLY_DEAD rejections. Stored as JSON-friendly list[dict]
    # (CipherDiscoverySuggestion.to_dict + a blocked_family key per entry)
    # rather than as a nested dataclass to avoid round-trip surprises
    # through the controller_state JSON column.
    last_escape_suggestions: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ControllerState:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Day 6: Pursuit leads
# ---------------------------------------------------------------------------


class PursuitLeadStatus(str, Enum):
    """Lifecycle of a lead opened by the Day 6 lead-pursuit evaluator.

    Lifecycle only — does NOT encode lead strength/kind. See
    `PursuitLead.source_verdict` for the hard-vs-soft distinction.
    """
    OPEN = "open"          # Freshly created, awaiting a theorist cycle to engage
    PURSUED = "pursued"    # A downstream theory referenced this lead
    STALE = "stale"        # Auto-closed after N cycles with no engagement


# Provenance tags for PursuitLead.source_verdict. Orthogonal to
# PursuitLeadStatus (which tracks lifecycle). A hard lead (PURSUE)
# originates from an evaluator verdict="pursue" and surfaces as priority
# context. A soft lead (SKIP_VARIANTS) originates from verdict="skip"
# with non-empty suggested_variants — the evaluator rejected this
# specific lead but preserved nearby variant directions that may be
# worth the theorist seeing next cycle. Capped smaller in rendering.
PURSUIT_SOURCE_PURSUE = "pursue"
PURSUIT_SOURCE_SKIP_VARIANTS = "skip_variants"
PURSUIT_SOURCE_VALUES = (PURSUIT_SOURCE_PURSUE, PURSUIT_SOURCE_SKIP_VARIANTS)


@dataclass
class PursuitLead:
    """
    A structured follow-up opened by the pursuit evaluator on a sub-signal
    result (6 <= crib_score <= 17). Distinct from TheoryRecord: a lead is
    "the question this result raises", while a theory is "the question
    itself." The separation lets a single source theory spawn multiple
    variant leads and keeps the audit trail clean.
    """
    lead_id: str = ""
    source_theory_id: str = ""
    source_cycle: int = 0
    crib_score: int = 0
    rationale: str = ""
    suggested_variants: list[str] = field(default_factory=list)
    status: PursuitLeadStatus = PursuitLeadStatus.OPEN
    source_verdict: str = PURSUIT_SOURCE_PURSUE
    opened_at: str = field(default_factory=_now_iso)
    closed_at: str = ""
    closed_cycle: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PursuitLead:
        d = dict(d)
        if "status" in d and isinstance(d["status"], str):
            try:
                d["status"] = PursuitLeadStatus(d["status"])
            except ValueError:
                d["status"] = PursuitLeadStatus.OPEN
        sv = d.get("source_verdict")
        if sv is not None and sv not in PURSUIT_SOURCE_VALUES:
            d["source_verdict"] = PURSUIT_SOURCE_PURSUE
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
