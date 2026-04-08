"""Bridge between composition framework and canonical scoring pipeline.

Hands intermediate/final texts into the existing score_candidate()
and score_candidate_free() paths without reimplementing any scoring.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from kryptos.composition.models import (
    CompositionResult,
    CompositionStack,
)
from kryptos.composition.constraints import select_scoring_mode
from kryptos.kernel.constants import CT, STORE_THRESHOLD
from kryptos.kernel.scoring.aggregate import (
    ScoreBreakdown,
    FreeScoreBreakdown,
    score_candidate,
    score_candidate_free,
)
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.crib_score import score_cribs


def score_composition(
    plaintext: str,
    stack: CompositionStack,
    intermediate_text: str = "",
    ngram_scorer: Any = None,
    word_scorer: Any = None,
) -> CompositionResult:
    """Score a composition result through the canonical pipeline.

    Selects anchored vs free scoring based on the composition's
    layer semantics, then wraps the result in a CompositionResult.
    """
    mode = select_scoring_mode(stack)
    ic_val = ic(plaintext)

    best_crib = 0
    best_breakdown: Optional[Dict[str, Any]] = None
    bean_pass = False

    if mode in ("anchored", "both"):
        anchored: ScoreBreakdown = score_candidate(
            plaintext,
            ngram_scorer=ngram_scorer,
            word_scorer=word_scorer,
        )
        if anchored.crib_score > best_crib:
            best_crib = anchored.crib_score
            best_breakdown = anchored.to_dict()
            bean_pass = anchored.bean_passed

    if mode in ("free", "both"):
        free: FreeScoreBreakdown = score_candidate_free(
            plaintext,
            ngram_scorer=ngram_scorer,
            word_scorer=word_scorer,
        )
        if free.crib_score > best_crib:
            best_crib = free.crib_score
            best_breakdown = free.to_dict()
            # Free scoring doesn't check Bean
            bean_pass = False

    ngram_val = None
    if best_breakdown:
        ngram_val = best_breakdown.get("ngram_score") or best_breakdown.get("ngram_per_char")

    return CompositionResult(
        stack=stack,
        intermediate_text=intermediate_text,
        plaintext=plaintext,
        crib_score=best_crib,
        bean_pass=bean_pass,
        ic_value=ic_val,
        ngram_score=ngram_val,
        score_breakdown=best_breakdown,
    )


def extract_nulls(ct: str) -> str:
    """Extract null positions from ciphertext, returning cipher-layer text."""
    from kryptos.kernel.constants import CONSENSUS_NULL_POSITIONS
    return "".join(c for i, c in enumerate(ct) if i not in CONSENSUS_NULL_POSITIONS)


def quick_crib_check(text: str, threshold: int = 3) -> bool:
    """Fast pre-screen: does the text have any crib matches above threshold?

    Used for early termination in inner loops. Much cheaper than full scoring.
    """
    return score_cribs(text) >= threshold
