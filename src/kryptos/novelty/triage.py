"""Triage layer — cheap tests to prioritize hypotheses.

Runs fast, lightweight tests on hypotheses before committing to
expensive full sweeps. Promotes top candidates and records all results.
"""
from __future__ import annotations

from typing import List, Optional

from kryptos.kernel.constants import CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT, NOISE_FLOOR
from kryptos.kernel.text import sanitize, text_to_nums
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, remove_additive_mask,
)
from kryptos.kernel.constraints.crib import crib_score
from kryptos.kernel.scoring.ic import ic
from kryptos.novelty.hypothesis import Hypothesis, HypothesisStatus


def triage_running_key(hyp: Hypothesis) -> Hypothesis:
    """Triage a running-key hypothesis by sampling offsets.

    Tests a sample of offsets and checks crib scores.
    """
    from pathlib import Path
    import random

    params = hyp.transform_stack[0].get("params", {})
    source_path = params.get("source_path", "")
    variant_name = hyp.transform_stack[0].get("type", "vigenere")

    try:
        raw = Path(source_path).read_text(errors="replace")
    except FileNotFoundError:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = f"Source file not found: {source_path}"
        return hyp

    clean = sanitize(raw)
    if len(clean) < CT_LEN:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = "Source text too short"
        return hyp

    n_offsets = len(clean) - CT_LEN + 1
    sample_size = min(200, n_offsets)

    rng = random.Random(42)  # Deterministic seed
    offsets = rng.sample(range(n_offsets), sample_size)

    best_score = 0
    best_offset = 0
    scores: list[int] = []

    for offset in offsets:
        key = text_to_nums(clean[offset:offset + CT_LEN])
        pt = decrypt_text(CT, key, CipherVariant(variant_name))
        sc = crib_score(pt)
        scores.append(sc)
        if sc > best_score:
            best_score = sc
            best_offset = offset

    avg_score = sum(scores) / len(scores) if scores else 0
    above_noise = sum(1 for s in scores if s > NOISE_FLOOR)

    # Score: ratio of best to theoretical max, boosted by above-noise count
    triage = min(1.0, best_score / 24.0 + above_noise / sample_size * 0.1)

    hyp.triage_score = triage
    hyp.triage_detail = (
        f"Sampled {sample_size}/{n_offsets} offsets. "
        f"Best: {best_score}/24 at offset {best_offset}. "
        f"Avg: {avg_score:.1f}. Above noise: {above_noise}/{sample_size}."
    )

    if best_score >= 10:
        hyp.status = HypothesisStatus.PROMOTED
    elif best_score > NOISE_FLOOR:
        hyp.status = HypothesisStatus.TRIAGED
    else:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.elimination_reason = f"Best score {best_score} at noise floor"

    return hyp


def triage_simple_key(hyp: Hypothesis) -> Hypothesis:
    """Triage a hypothesis with a fixed key (date-derived, etc.)."""
    params = hyp.transform_stack[0].get("params", {})
    key = params.get("key", [])
    variant_name = hyp.transform_stack[0].get("type", "vigenere")

    if not key:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = "No key provided"
        return hyp

    pt = decrypt_text(CT, key, CipherVariant(variant_name))
    sc = crib_score(pt)
    text_ic = ic(pt)

    hyp.triage_score = sc / 24.0
    hyp.triage_detail = f"Score: {sc}/24, IC: {text_ic:.4f}"

    if sc >= 10:
        hyp.status = HypothesisStatus.PROMOTED
    elif sc > NOISE_FLOOR:
        hyp.status = HypothesisStatus.TRIAGED
    else:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.elimination_reason = f"Score {sc} at noise floor"

    return hyp


def triage_hypothesis(hyp: Hypothesis) -> Hypothesis:
    """Route a hypothesis to the appropriate triage function."""
    if not hyp.transform_stack:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = "No transform stack defined"
        return hyp

    first_type = hyp.transform_stack[0].get("type", "")
    params = hyp.transform_stack[0].get("params", {})

    if params.get("key_source") == "running_key":
        return triage_running_key(hyp)
    elif params.get("key"):
        return triage_simple_key(hyp)
    else:
        # Default: mark as triaged with neutral score
        hyp.status = HypothesisStatus.TRIAGED
        hyp.triage_score = 0.5
        hyp.triage_detail = "No specific triage available; needs manual review"
        return hyp


def triage_batch(hypotheses: List[Hypothesis]) -> List[Hypothesis]:
    """Triage a batch of hypotheses and return sorted by priority."""
    results = [triage_hypothesis(h) for h in hypotheses]
    # Sort by priority score (highest first)
    results.sort(key=lambda h: h.priority_score, reverse=True)
    return results
