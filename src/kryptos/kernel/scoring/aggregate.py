"""Aggregate scoring — combines multiple scoring dimensions.

This is the SINGLE canonical scoring path. All experiments must use this
to produce comparable, explainable results.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from kryptos.kernel.constants import CT, CRIB_DICT, N_CRIBS
from kryptos.kernel.scoring.ic import ic, ic_score
from kryptos.kernel.scoring.crib_score import (
    score_cribs, score_cribs_detailed, is_breakthrough,
)
from kryptos.kernel.constraints.bean import BeanResult


@dataclass
class ScoreBreakdown:
    """Explainable composite score for a candidate."""

    # Crib matching
    crib_score: int = 0
    crib_total: int = N_CRIBS
    ene_score: int = 0
    bc_score: int = 0
    crib_classification: str = "noise"

    # IC analysis
    ic_value: float = 0.0
    ic_score_normalized: float = 0.0

    # N-gram quality (optional, may be None if not computed)
    ngram_score: Optional[float] = None
    ngram_per_char: Optional[float] = None

    # Bean constraints
    bean_passed: bool = False
    bean_detail: Optional[str] = None

    # Composite
    is_breakthrough: bool = False

    @property
    def summary(self) -> str:
        parts = [
            f"cribs={self.crib_score}/{self.crib_total}",
            f"ENE={self.ene_score}/13",
            f"BC={self.bc_score}/11",
            f"IC={self.ic_value:.4f}",
            f"bean={'PASS' if self.bean_passed else 'FAIL'}",
            f"[{self.crib_classification}]",
        ]
        if self.ngram_per_char is not None:
            parts.append(f"ngram={self.ngram_per_char:.2f}")
        return " | ".join(parts)

    def to_dict(self) -> dict:
        return {
            "crib_score": self.crib_score,
            "crib_total": self.crib_total,
            "ene_score": self.ene_score,
            "bc_score": self.bc_score,
            "crib_classification": self.crib_classification,
            "ic_value": self.ic_value,
            "ic_score_normalized": self.ic_score_normalized,
            "ngram_score": self.ngram_score,
            "ngram_per_char": self.ngram_per_char,
            "bean_passed": self.bean_passed,
            "bean_detail": self.bean_detail,
            "is_breakthrough": self.is_breakthrough,
        }


def score_candidate(
    plaintext: str,
    bean_result: Optional[BeanResult] = None,
    ngram_scorer=None,
) -> ScoreBreakdown:
    """Score a plaintext candidate through the canonical evaluation path.

    This is THE function that all experiments must use for scoring.

    Args:
        plaintext: Candidate plaintext (uppercase A-Z)
        bean_result: Optional pre-computed Bean result
        ngram_scorer: Optional NgramScorer for language quality

    Returns:
        ScoreBreakdown with full diagnostic information
    """
    # Crib scoring
    detail = score_cribs_detailed(plaintext)
    crib_sc = detail["score"]

    # IC
    ic_val = ic(plaintext)
    ic_sc = ic_score(plaintext)

    # Bean
    bean_pass = bean_result.passed if bean_result is not None else False
    bean_det = bean_result.summary if bean_result is not None else None

    # N-gram (optional)
    ngram_total = None
    ngram_pc = None
    if ngram_scorer is not None:
        try:
            ngram_total = ngram_scorer.score(plaintext)
            ngram_pc = ngram_scorer.score_per_char(plaintext)
        except Exception:
            pass

    return ScoreBreakdown(
        crib_score=crib_sc,
        crib_total=N_CRIBS,
        ene_score=detail["ene_score"],
        bc_score=detail["bc_score"],
        crib_classification=detail["classification"],
        ic_value=ic_val,
        ic_score_normalized=ic_sc,
        ngram_score=ngram_total,
        ngram_per_char=ngram_pc,
        bean_passed=bean_pass,
        bean_detail=bean_det,
        is_breakthrough=is_breakthrough(crib_sc, bean_pass),
    )
