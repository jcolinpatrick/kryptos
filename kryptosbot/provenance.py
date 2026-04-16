"""
Provenance and epistemic-status layer for the KryptosBot research controller.

First-class enums and dataclasses that make epistemic hedging structural
rather than author-remembered. Every claim the controller uses carries an
explicit epistemic_class, scope conditions, verification status, allowed
downstream uses, and a dependency chain.

This module is the shared vocabulary. claims_registry.py holds canonical
entries, claim_policy.py implements gates, and claim_rendering.py handles
auto-hedging output.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class EpistemicClass(str, Enum):
    PUBLIC_FACT = "public_fact"
    PRIMARY_SOURCE_FACT = "primary_source_fact"
    PROJECT_CONVENTION = "project_convention"
    H1_CONDITIONAL_DERIVATION = "h1_conditional_derivation"
    PROJECT_REVERIFIED_STATISTICAL_ANOMALY = "project_reverified_statistical_anomaly"
    BEAN_REPORTED_NOT_RERUN = "bean_reported_not_rerun"
    PHYSICAL_FACT = "physical_fact"
    INTERPRETIVE_PHYSICAL_OBSERVATION = "interpretive_physical_observation"
    CONDITIONAL_ELIMINATION = "conditional_elimination"
    STRUCTURAL_ELIMINATION = "structural_elimination"
    INTERNAL_RESULT = "internal_result"
    RETIRED_CLAIM = "retired_claim"
    HYPOTHESIS = "hypothesis"
    DISPROVED_HYPOTHESIS = "disproved_hypothesis"


class VerificationStatus(str, Enum):
    PROJECT_VERIFIED = "project_verified"
    EXTERNAL_AUTHOR_REPORTED = "external_author_reported"
    PRIMARY_SOURCE_DOCUMENTED = "primary_source_documented"
    INTERPRETIVE = "interpretive"
    PENDING_VERIFICATION = "pending_verification"
    RETIRED = "retired"


class ReproducibilityStatus(str, Enum):
    REPRODUCIBLE_FROM_CODE = "reproducible_from_code"
    REPRODUCIBLE_WITH_INSTRUCTIONS = "reproducible_with_instructions"
    NON_REPRODUCIBLE = "non_reproducible"
    NOT_APPLICABLE = "not_applicable"


class AllowedUse(str, Enum):
    SUMMARY = "summary"
    HARD_CONSTRAINT = "hard_constraint"
    RANKING_FEATURE = "ranking_feature"
    NULL_BASELINE = "null_baseline"
    ELIMINATION_BASIS = "elimination_basis"
    PROMPT_CONTEXT = "prompt_context"


# ---------------------------------------------------------------------------
# ScopeConditions
# ---------------------------------------------------------------------------


@dataclass
class ScopeConditions:
    """Machine-readable scope conditions that propagate automatically.

    All fields default to None (unknown/not-applicable) so omitting a field
    does NOT create an implicit True. Set explicit True/False where known.
    """
    assumes_direct_positional_crib_alignment: Optional[bool] = None
    assumes_canonical_97_char_transcription: Optional[bool] = None
    assumes_additive_cipher_family: Optional[bool] = None
    assumes_specific_variant: Optional[str] = None
    assumes_beaufort_a0: Optional[bool] = None
    assumes_modeled_crib_positions: Optional[bool] = None
    applies_only_to_crib_positions: Optional[bool] = None
    applies_to_entire_cipher: Optional[bool] = None
    survives_transposition: Optional[bool] = None
    valid_under_multilayer_composition: Optional[bool] = None
    independently_project_rerun: Optional[bool] = None
    depends_on_external_author_statistic: Optional[bool] = None
    uses_post_hoc_subset_selection: Optional[bool] = None
    multiplicity_corrected_in_project: Optional[bool] = None
    scope_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScopeConditions:
        if not d:
            return cls()
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# ProvenanceClaim
# ---------------------------------------------------------------------------


@dataclass
class ProvenanceClaim:
    """A first-class claim with full provenance metadata.

    Unit of the canonical claims registry. Renderers, policy gates, and
    theory triage all read from this structure rather than hand-written prose.
    """
    claim_id: str = ""
    claim_text: str = ""
    epistemic_class: EpistemicClass = EpistemicClass.HYPOTHESIS
    scope_conditions: ScopeConditions = field(default_factory=ScopeConditions)
    source_basis: str = ""
    verification_status: VerificationStatus = VerificationStatus.PENDING_VERIFICATION
    reproducibility_status: ReproducibilityStatus = ReproducibilityStatus.NOT_APPLICABLE
    dependency_chain: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    allowed_downstream_uses: list[AllowedUse] = field(default_factory=list)
    last_verified_at: str = ""
    last_verified_by: str = ""
    evidence_links: list[str] = field(default_factory=list)
    related_anomaly_id: str = ""
    related_family_id: str = ""
    tags: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_text": self.claim_text,
            "epistemic_class": self.epistemic_class.value,
            "scope_conditions": self.scope_conditions.to_dict(),
            "source_basis": self.source_basis,
            "verification_status": self.verification_status.value,
            "reproducibility_status": self.reproducibility_status.value,
            "dependency_chain": list(self.dependency_chain),
            "caveats": list(self.caveats),
            "allowed_downstream_uses": [u.value for u in self.allowed_downstream_uses],
            "last_verified_at": self.last_verified_at,
            "last_verified_by": self.last_verified_by,
            "evidence_links": list(self.evidence_links),
            "related_anomaly_id": self.related_anomaly_id,
            "related_family_id": self.related_family_id,
            "tags": list(self.tags),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProvenanceClaim:
        d = dict(d)
        if "epistemic_class" in d and isinstance(d["epistemic_class"], str):
            d["epistemic_class"] = EpistemicClass(d["epistemic_class"])
        if "verification_status" in d and isinstance(d["verification_status"], str):
            d["verification_status"] = VerificationStatus(d["verification_status"])
        if "reproducibility_status" in d and isinstance(d["reproducibility_status"], str):
            d["reproducibility_status"] = ReproducibilityStatus(d["reproducibility_status"])
        if "allowed_downstream_uses" in d:
            d["allowed_downstream_uses"] = [
                AllowedUse(u) if isinstance(u, str) else u
                for u in d["allowed_downstream_uses"]
            ]
        if "scope_conditions" in d and isinstance(d["scope_conditions"], dict):
            d["scope_conditions"] = ScopeConditions.from_dict(d["scope_conditions"])
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
