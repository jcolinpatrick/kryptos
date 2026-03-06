"""Benchmark data structures and normalization rules."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def normalize_text(text: str, *, strip_spaces: bool = True) -> str:
    """Normalize text to uppercase A-Z only.

    Args:
        text: Input text.
        strip_spaces: If True (default), remove whitespace before filtering.

    Returns:
        String containing only uppercase A-Z characters.
    """
    text = text.upper()
    if strip_spaces:
        text = re.sub(r"\s+", "", text)
    return re.sub(r"[^A-Z]", "", text)


@dataclass
class BenchmarkCase:
    """One test case in a benchmark suite."""

    case_id: str
    ciphertext: str
    script: str  # path to attack script, relative to project root
    expected_plaintext: str = ""
    expected_key: str = ""
    expected_family: str = ""
    label: str = ""
    params: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.ciphertext = normalize_text(self.ciphertext)
        if self.expected_plaintext:
            self.expected_plaintext = normalize_text(self.expected_plaintext)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "case_id": self.case_id,
            "ciphertext": self.ciphertext,
            "script": self.script,
        }
        if self.expected_plaintext:
            d["expected_plaintext"] = self.expected_plaintext
        if self.expected_key:
            d["expected_key"] = self.expected_key
        if self.expected_family:
            d["expected_family"] = self.expected_family
        if self.label:
            d["label"] = self.label
        if self.params:
            d["params"] = self.params
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BenchmarkCase:
        return cls(
            case_id=data["case_id"],
            ciphertext=data["ciphertext"],
            script=data["script"],
            expected_plaintext=data.get("expected_plaintext", ""),
            expected_key=data.get("expected_key", ""),
            expected_family=data.get("expected_family", ""),
            label=data.get("label", ""),
            params=data.get("params", {}),
        )


@dataclass
class CandidateResult:
    """One candidate produced by an attack script."""

    score: float
    plaintext: str
    method: str
    canonical_score: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "score": self.score,
            "plaintext": self.plaintext,
            "method": self.method,
        }
        if self.canonical_score is not None:
            d["canonical_score"] = self.canonical_score
        return d


@dataclass
class BenchmarkResult:
    """Result of running one benchmark case."""

    case_id: str
    status: str  # "success" | "error" | "no_results"
    elapsed_s: float = 0.0
    n_candidates: int = 0
    top_candidates: List[CandidateResult] = field(default_factory=list)
    predicted_plaintext: str = ""
    predicted_family: str = ""
    predicted_key: str = ""
    match_plaintext: bool = False
    match_rank: int = -1  # 1-indexed rank where expected PT was found, -1 if absent
    error: str = ""
    script: str = ""
    ciphertext: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    validation: Dict[str, Any] = field(default_factory=dict)
    segmentation: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "case_id": self.case_id,
            "status": self.status,
            "elapsed_s": round(self.elapsed_s, 4),
            "n_candidates": self.n_candidates,
            "top_candidates": [c.to_dict() for c in self.top_candidates],
            "predicted_plaintext": self.predicted_plaintext,
            "predicted_family": self.predicted_family,
            "predicted_key": self.predicted_key,
            "match_plaintext": self.match_plaintext,
            "match_rank": self.match_rank,
            "error": self.error,
            "script": self.script,
            "ciphertext": self.ciphertext,
            "metadata": self.metadata,
        }
        if self.validation:
            d["validation"] = self.validation
        if self.segmentation:
            d["segmentation"] = self.segmentation
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BenchmarkResult:
        candidates = [
            CandidateResult(
                score=c["score"],
                plaintext=c["plaintext"],
                method=c["method"],
                canonical_score=c.get("canonical_score"),
            )
            for c in data.get("top_candidates", [])
        ]
        return cls(
            case_id=data["case_id"],
            status=data["status"],
            elapsed_s=data.get("elapsed_s", 0.0),
            n_candidates=data.get("n_candidates", 0),
            top_candidates=candidates,
            predicted_plaintext=data.get("predicted_plaintext", ""),
            predicted_family=data.get("predicted_family", ""),
            predicted_key=data.get("predicted_key", ""),
            match_plaintext=data.get("match_plaintext", False),
            match_rank=data.get("match_rank", -1),
            error=data.get("error", ""),
            script=data.get("script", ""),
            ciphertext=data.get("ciphertext", ""),
            metadata=data.get("metadata", {}),
            validation=data.get("validation", {}),
            segmentation=data.get("segmentation", {}),
        )
