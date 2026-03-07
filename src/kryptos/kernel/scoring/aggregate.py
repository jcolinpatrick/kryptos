"""Aggregate scoring — combines multiple scoring dimensions.

This is the SINGLE canonical scoring path. All experiments must use this
to produce comparable, explainable results.

Two scoring modes:
  score_candidate()      — anchored: cribs at fixed positions 21-33, 63-73
  score_candidate_free() — free: cribs searched anywhere in candidate text

The anchored scorer is the original. The free scorer was added for the
first-principles audit (2026-02-26) to test whether fixed crib positions
are a hidden dependency masking true positives.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from kryptos.kernel.constants import CT, CRIB_DICT, N_CRIBS
from kryptos.kernel.scoring.ic import ic, ic_score
from kryptos.kernel.scoring.crib_score import (
    score_cribs, score_cribs_detailed, is_breakthrough,
)
from kryptos.kernel.scoring.free_crib import (
    FreeCribResult, score_free, score_free_fast,
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

    # Word-level scoring (optional)
    word_coverage: Optional[float] = None
    word_score: Optional[float] = None
    word_count: Optional[int] = None
    longest_word: Optional[int] = None

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
        if self.word_coverage is not None:
            parts.append(f"words={self.word_coverage:.0%}")
        return " | ".join(parts)

    def to_dict(self) -> dict:
        d = {
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
        if self.word_coverage is not None:
            d["word_coverage"] = self.word_coverage
            d["word_score"] = self.word_score
            d["word_count"] = self.word_count
            d["longest_word"] = self.longest_word
        return d


def score_candidate(
    plaintext: str,
    bean_result: Optional[BeanResult] = None,
    ngram_scorer=None,
    word_scorer=None,
) -> ScoreBreakdown:
    """Score a plaintext candidate through the canonical evaluation path.

    This is THE function that all experiments must use for scoring.

    Args:
        plaintext: Candidate plaintext (uppercase A-Z)
        bean_result: Optional pre-computed Bean result
        ngram_scorer: Optional NgramScorer for language quality
        word_scorer: Optional WordScorer for word-level English detection

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

    # Word-level scoring (optional)
    w_coverage = None
    w_score = None
    w_count = None
    w_longest = None
    if word_scorer is not None:
        try:
            wr = word_scorer.score(plaintext)
            w_coverage = wr.coverage
            w_score = wr.weighted_score
            w_count = wr.word_count
            w_longest = wr.longest
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
        word_coverage=w_coverage,
        word_score=w_score,
        word_count=w_count,
        longest_word=w_longest,
        bean_passed=bean_pass,
        bean_detail=bean_det,
        is_breakthrough=is_breakthrough(crib_sc, bean_pass),
    )


# ── Position-free scoring ────────────────────────────────────────────────


@dataclass
class FreeScoreBreakdown:
    """Score breakdown using position-free crib matching.

    Unlike ScoreBreakdown, this searches for cribs anywhere in the text.
    Use this when the assumption of fixed crib positions is under test.
    """
    # Free crib matching
    free_crib: FreeCribResult = field(default_factory=FreeCribResult)
    crib_score: int = 0           # 0, 11, 13, or 24
    ene_found: bool = False
    bc_found: bool = False
    both_found: bool = False
    canonical_positions: bool = False

    # IC analysis
    ic_value: float = 0.0
    ic_score_normalized: float = 0.0

    # N-gram quality
    ngram_score: Optional[float] = None
    ngram_per_char: Optional[float] = None

    # Word-level scoring (optional)
    word_coverage: Optional[float] = None
    word_score: Optional[float] = None
    word_count: Optional[int] = None
    longest_word: Optional[int] = None

    # Classification
    crib_classification: str = "noise"
    is_breakthrough: bool = False

    @property
    def summary(self) -> str:
        parts = [
            f"free_cribs={self.crib_score}/24",
            f"ENE={'YES' if self.ene_found else 'no'}",
            f"BC={'YES' if self.bc_found else 'no'}",
            f"IC={self.ic_value:.4f}",
        ]
        if self.both_found and self.free_crib.gap is not None:
            parts.append(f"gap={self.free_crib.gap}")
        if self.canonical_positions:
            parts.append("CANONICAL")
        parts.append(f"[{self.crib_classification}]")
        if self.ngram_per_char is not None:
            parts.append(f"ngram={self.ngram_per_char:.2f}")
        if self.word_coverage is not None:
            parts.append(f"words={self.word_coverage:.0%}")
        return " | ".join(parts)

    def to_dict(self) -> dict:
        d = {
            "crib_score": self.crib_score,
            "ene_found": self.ene_found,
            "bc_found": self.bc_found,
            "both_found": self.both_found,
            "canonical_positions": self.canonical_positions,
            "ic_value": self.ic_value,
            "ic_score_normalized": self.ic_score_normalized,
            "ngram_score": self.ngram_score,
            "ngram_per_char": self.ngram_per_char,
            "crib_classification": self.crib_classification,
            "is_breakthrough": self.is_breakthrough,
        }
        if self.word_coverage is not None:
            d["word_coverage"] = self.word_coverage
            d["word_score"] = self.word_score
            d["word_count"] = self.word_count
            d["longest_word"] = self.longest_word
        if self.free_crib.ene_offsets:
            d["ene_offsets"] = self.free_crib.ene_offsets
        if self.free_crib.bc_offsets:
            d["bc_offsets"] = self.free_crib.bc_offsets
        if self.free_crib.gap is not None:
            d["gap"] = self.free_crib.gap
        return d


def score_candidate_free(
    plaintext: str,
    ngram_scorer=None,
    word_scorer=None,
) -> FreeScoreBreakdown:
    """Score a plaintext candidate using position-free crib matching.

    Searches for EASTNORTHEAST and BERLINCLOCK anywhere in the text.
    Does NOT use Bean constraints (they depend on fixed positions).
    Does NOT use anchored crib positions.

    Use this when testing whether fixed crib positions are a hidden
    dependency in your elimination logic.

    Args:
        plaintext: Candidate plaintext (uppercase A-Z)
        ngram_scorer: Optional NgramScorer for language quality
        word_scorer: Optional WordScorer for word-level English detection

    Returns:
        FreeScoreBreakdown with full diagnostic information
    """
    text = plaintext.upper()

    # Free crib scoring
    fcr = score_free(text)

    # IC
    ic_val = ic(text)
    ic_sc = ic_score(text)

    # N-gram (optional)
    ngram_total = None
    ngram_pc = None
    if ngram_scorer is not None:
        try:
            ngram_total = ngram_scorer.score(text)
            ngram_pc = ngram_scorer.score_per_char(text)
        except Exception:
            pass

    # Word-level scoring (optional)
    w_coverage = None
    w_score = None
    w_count = None
    w_longest = None
    if word_scorer is not None:
        try:
            wr = word_scorer.score(text)
            w_coverage = wr.coverage
            w_score = wr.weighted_score
            w_count = wr.word_count
            w_longest = wr.longest
        except Exception:
            pass

    # Classification
    sc = fcr.score
    if sc >= 24:
        classification = "breakthrough"
    elif sc >= 13:
        classification = "signal"
    elif sc >= 11:
        classification = "interesting"
    else:
        classification = "noise"

    return FreeScoreBreakdown(
        free_crib=fcr,
        crib_score=sc,
        ene_found=fcr.ene_found,
        bc_found=fcr.bc_found,
        both_found=fcr.both_found,
        canonical_positions=fcr.canonical_positions,
        ic_value=ic_val,
        ic_score_normalized=ic_sc,
        ngram_score=ngram_total,
        ngram_per_char=ngram_pc,
        word_coverage=w_coverage,
        word_score=w_score,
        word_count=w_count,
        longest_word=w_longest,
        crib_classification=classification,
        is_breakthrough=(sc >= 24),
    )
