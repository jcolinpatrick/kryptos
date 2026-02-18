"""Hypothesis schema — structured representation of cipher hypotheses.

Every hypothesis is a falsifiable claim about the K4 cipher, with
metadata for tracking, prioritization, and reproducibility.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class HypothesisStatus(str, Enum):
    """Lifecycle status of a hypothesis."""
    PROPOSED = "proposed"        # Generated but not yet triaged
    TRIAGED = "triaged"          # Cheap tests run, awaiting full evaluation
    PROMOTED = "promoted"        # Passed triage, queued for full sweep
    TESTING = "testing"          # Currently being tested
    SURVIVED = "survived"        # Passed some tests, not yet eliminated
    ELIMINATED = "eliminated"    # Definitively ruled out
    BREAKTHROUGH = "breakthrough"  # Potential solution found


class ResearchQuestion(str, Enum):
    """Research questions from docs/research_questions.md."""
    RQ1_CIPHER_TYPE = "RQ-1"
    RQ2_KEY_SOURCE = "RQ-2"
    RQ3_TRANSPOSITION = "RQ-3"
    RQ4_THE_POINT = "RQ-4"
    RQ5_EGYPT_BERLIN = "RQ-5"
    RQ6_DELIVERING_MESSAGE = "RQ-6"
    RQ7_PRE_ENE = "RQ-7"
    RQ8_K3_CHANGE = "RQ-8"
    RQ9_K5 = "RQ-9"
    RQ10_PHYSICAL = "RQ-10"
    RQ11_KEYSTREAM = "RQ-11"
    RQ12_NONSTANDARD_ALPHABET = "RQ-12"
    RQ13_READING_DIRECTION = "RQ-13"


# Priority weights per tier (from research_questions.md)
RQ_WEIGHTS: Dict[ResearchQuestion, int] = {
    ResearchQuestion.RQ1_CIPHER_TYPE: 10,
    ResearchQuestion.RQ2_KEY_SOURCE: 10,
    ResearchQuestion.RQ3_TRANSPOSITION: 10,
    ResearchQuestion.RQ4_THE_POINT: 5,
    ResearchQuestion.RQ5_EGYPT_BERLIN: 5,
    ResearchQuestion.RQ6_DELIVERING_MESSAGE: 5,
    ResearchQuestion.RQ7_PRE_ENE: 5,
    ResearchQuestion.RQ8_K3_CHANGE: 2,
    ResearchQuestion.RQ9_K5: 1,
    ResearchQuestion.RQ10_PHYSICAL: 2,
    ResearchQuestion.RQ11_KEYSTREAM: 1,
    ResearchQuestion.RQ12_NONSTANDARD_ALPHABET: 1,
    ResearchQuestion.RQ13_READING_DIRECTION: 1,
}


@dataclass
class Hypothesis:
    """A falsifiable hypothesis about the K4 cipher.

    Every hypothesis must be:
    - Testable (has a transform stack or test procedure)
    - Falsifiable (has expected signatures for success/failure)
    - Traceable (knows why it was proposed and what it addresses)
    """

    # Identity
    description: str
    transform_stack: List[Dict[str, Any]] = field(default_factory=list)

    # Research context
    research_questions: List[ResearchQuestion] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    provenance: str = ""  # Why was this proposed?

    # Expected outcomes
    expected_signatures: Dict[str, Any] = field(default_factory=dict)
    triage_tests: List[Dict[str, Any]] = field(default_factory=list)

    # Compute budget
    estimated_configs: int = 0  # How many configs to test
    estimated_seconds: float = 0.0  # Rough compute estimate

    # Lifecycle
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    triage_score: float = 0.0  # Set after triage (0-1)
    triage_detail: str = ""
    test_results: Dict[str, Any] = field(default_factory=dict)
    elimination_reason: str = ""

    # Metadata
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: List[str] = field(default_factory=list)

    @property
    def hypothesis_id(self) -> str:
        """Stable hash from description + transform stack."""
        payload = json.dumps(
            {"desc": self.description, "stack": self.transform_stack},
            sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    @property
    def priority_score(self) -> float:
        """Compute priority for the novelty engine's queue.

        priority = sum(RQ weights) * triage_score / (1 + log(compute_cost))
        """
        import math
        rq_weight = sum(RQ_WEIGHTS.get(rq, 1) for rq in self.research_questions)
        if rq_weight == 0:
            rq_weight = 1
        cost_factor = 1.0 + math.log1p(max(1, self.estimated_configs))
        return rq_weight * max(0.01, self.triage_score) / cost_factor

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["hypothesis_id"] = self.hypothesis_id
        d["priority_score"] = self.priority_score
        d["research_questions"] = [rq.value for rq in self.research_questions]
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Hypothesis":
        data = dict(data)
        data.pop("hypothesis_id", None)
        data.pop("priority_score", None)
        if "research_questions" in data:
            data["research_questions"] = [
                ResearchQuestion(rq) if isinstance(rq, str) else rq
                for rq in data["research_questions"]
            ]
        if "status" in data and isinstance(data["status"], str):
            data["status"] = HypothesisStatus(data["status"])
        return cls(**data)
