"""Dataclasses for outer/inner families and evaluation results."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ProvenanceClass(str, Enum):
    STRUCTURAL = "structural"
    H1_CONDITIONAL = "h1_conditional"
    PROJECT_RERUN = "project_rerun"
    BEAN_REPORTED = "bean_reported"
    EXPLORATORY = "exploratory"


class InnerMixingClass(str, Enum):
    NEAR_IDENTITY = "near_identity"
    WEAKLY_MIXING = "weakly_mixing"
    STRONGLY_MIXING = "strongly_mixing"


@dataclass
class OuterFamily:
    """An outer stego/selection/projection layer instance."""

    family_id: str
    name: str
    description: str
    parameters: Dict[str, Any]
    parameter_space_size: int
    complexity_score: float
    breaks_direct_positional_alignment: bool
    is_post_hoc_selected: bool
    selection_pool_size: int
    provenance: ProvenanceClass


@dataclass
class InnerFamily:
    """An inner encipherment layer instance."""

    family_id: str
    name: str
    description: str
    parameters: Dict[str, Any]
    parameter_space_size: int
    complexity_score: float
    mixing_class: InnerMixingClass
    preserves_letter_distance: bool
    provenance: ProvenanceClass


@dataclass
class CompositionProfile:
    """A specific (outer, inner) composition under test."""

    profile_id: str
    outer: OuterFamily
    inner: InnerFamily
    total_complexity: float
    is_elimination_grade: bool
    notes: str = ""


@dataclass
class EvaluationResult:
    """Blind evaluation output for one composition profile."""

    profile_id: str
    candidate_text: str
    crib_compatibility_score: int
    bean_compatibility: Optional[bool]
    bean_compatibility_scope_note: str
    width21_repeat_count: int
    width21_zscore: float
    width_spectrum: Dict[int, int]
    cherry_picked_width: bool
    stehle_local_delta5_count: int
    stehle_position_55_63_match: bool
    weak_identity_preservation: float
    english_likeness: float
    novelty_against_known_eliminations: bool
    is_joint_anomaly_success: bool
    multiplicity_penalty: float
    provenance: ProvenanceClass = ProvenanceClass.PROJECT_RERUN
    flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Enum -> string
        d["provenance"] = self.provenance.value
        # int-keyed dict -> str-keyed for JSON
        d["width_spectrum"] = {str(k): v for k, v in self.width_spectrum.items()}
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvaluationResult":
        data = dict(d)
        data["provenance"] = ProvenanceClass(data.get("provenance", "project_rerun"))
        data["width_spectrum"] = {
            int(k): v for k, v in data.get("width_spectrum", {}).items()
        }
        return cls(**data)
