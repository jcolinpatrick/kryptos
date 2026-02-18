"""Canonical evaluation pipeline — THE single truth path.

Every experiment in the repo MUST use evaluate_candidate() or
evaluate_pipeline() to produce scores. This ensures all results
are comparable and consistently validated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from kryptos.kernel.constants import CT, CRIB_DICT, CT_LEN
from kryptos.kernel.alphabet import Alphabet
from kryptos.kernel.transforms.vigenere import CipherVariant, recover_key_at_positions
from kryptos.kernel.transforms.compose import PipelineConfig, build_pipeline
from kryptos.kernel.constraints.crib import (
    compute_implied_keys, check_vimark_consistency, crib_score,
)
from kryptos.kernel.constraints.bean import (
    BeanResult, verify_bean, verify_bean_simple, expand_keystream_vimark,
)
from kryptos.kernel.scoring.aggregate import ScoreBreakdown, score_candidate


@dataclass
class EvaluationResult:
    """Complete evaluation result for a candidate."""
    plaintext: str
    score: ScoreBreakdown
    pipeline_config: Optional[Dict[str, Any]] = None
    implied_keystream: Optional[Dict[int, int]] = None
    primer: Optional[Tuple[int, ...]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_breakthrough(self) -> bool:
        return self.score.is_breakthrough

    @property
    def summary(self) -> str:
        return self.score.summary


def evaluate_candidate(
    plaintext: str,
    keystream: Optional[List[int]] = None,
    bean_result: Optional[BeanResult] = None,
    ngram_scorer=None,
    metadata: Optional[Dict[str, Any]] = None,
) -> EvaluationResult:
    """Evaluate a plaintext candidate through the canonical path.

    This is the PRIMARY entry point for scoring. All experiments should
    funnel through this function.

    Args:
        plaintext: Candidate plaintext (uppercase A-Z, len >= 97)
        keystream: Optional full keystream for Bean checking
        bean_result: Optional pre-computed Bean result
        ngram_scorer: Optional NgramScorer
        metadata: Optional metadata dict

    Returns:
        EvaluationResult with full diagnostics
    """
    # If we have a keystream but no bean result, compute it
    if keystream is not None and bean_result is None:
        bean_result = verify_bean(keystream)

    score = score_candidate(plaintext, bean_result, ngram_scorer)

    return EvaluationResult(
        plaintext=plaintext,
        score=score,
        metadata=metadata or {},
    )


def evaluate_with_key(
    ct_text: str,
    key: List[int],
    variant: CipherVariant = CipherVariant.VIGENERE,
    ngram_scorer=None,
    metadata: Optional[Dict[str, Any]] = None,
) -> EvaluationResult:
    """Evaluate by decrypting ciphertext with a given key.

    Handles the full chain: decrypt -> score cribs -> check Bean -> aggregate.
    """
    from kryptos.kernel.transforms.vigenere import decrypt_text

    plaintext = decrypt_text(ct_text, key, variant)
    bean_result = verify_bean(key)
    score = score_candidate(plaintext, bean_result, ngram_scorer)

    return EvaluationResult(
        plaintext=plaintext,
        score=score,
        implied_keystream={i: k for i, k in enumerate(key) if i < len(key)},
        metadata=metadata or {},
    )


def evaluate_pipeline(
    config: PipelineConfig,
    ct_text: str = CT,
    variant: CipherVariant = CipherVariant.VIGENERE,
    period: int = 5,
    pa: Optional[Alphabet] = None,
    ca: Optional[Alphabet] = None,
    ngram_scorer=None,
    metadata: Optional[Dict[str, Any]] = None,
) -> EvaluationResult:
    """Evaluate a complete transform pipeline.

    Applies the pipeline to ciphertext, then scores the result
    through the canonical evaluation path.
    """
    transform_fn = build_pipeline(config)
    intermediate = transform_fn(ct_text)

    # Compute implied keys at crib positions
    implied = compute_implied_keys(intermediate, variant, pa, ca)
    key_dict = dict(implied)

    # Check Vimark consistency
    n_consistent, total, primer = check_vimark_consistency(implied, period)

    # Bean check
    bean_result: Optional[BeanResult] = None
    if primer is not None:
        ks = expand_keystream_vimark(primer, CT_LEN)
        bean_result = verify_bean(ks)

    # Crib score on intermediate text directly
    from kryptos.kernel.transforms.vigenere import decrypt_text
    if primer is not None:
        ks = expand_keystream_vimark(primer, CT_LEN)
        plaintext = decrypt_text(intermediate, ks, variant)
    else:
        plaintext = intermediate  # Can't decrypt without a key

    score = score_candidate(plaintext, bean_result, ngram_scorer)

    return EvaluationResult(
        plaintext=plaintext,
        score=score,
        pipeline_config=config.to_dict(),
        implied_keystream=key_dict,
        primer=primer,
        metadata=metadata or {},
    )
