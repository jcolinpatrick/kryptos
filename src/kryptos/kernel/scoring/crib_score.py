"""Crib-based scoring — measures how well a candidate matches known plaintext."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    CRIB_DICT, CRIB_ENTRIES, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)


def score_cribs(text: str) -> int:
    """Count matching crib positions (0 to 24)."""
    return sum(
        1 for pos, ch in CRIB_DICT.items()
        if pos < len(text) and text[pos] == ch
    )


def score_cribs_detailed(text: str) -> Dict[str, object]:
    """Detailed crib scoring with breakdown.

    Returns dict with:
    - score: total matching positions
    - total: 24
    - ene_score: EASTNORTHEAST matches (0-13)
    - bc_score: BERLINCLOCK matches (0-11)
    - matched_positions: list of matching positions
    - failed_positions: list of non-matching positions with expected/actual
    - classification: 'noise' | 'interesting' | 'signal' | 'breakthrough'
    """
    matched: list[int] = []
    failed: list[dict] = []
    ene_score = 0
    bc_score = 0

    for pos, expected in CRIB_DICT.items():
        if pos < len(text) and text[pos] == expected:
            matched.append(pos)
            if 21 <= pos <= 33:
                ene_score += 1
            elif 63 <= pos <= 73:
                bc_score += 1
        else:
            actual = text[pos] if pos < len(text) else "?"
            failed.append({"pos": pos, "expected": expected, "actual": actual})

    score = len(matched)

    if score >= BREAKTHROUGH_THRESHOLD:
        classification = "breakthrough"
    elif score >= SIGNAL_THRESHOLD:
        classification = "signal"
    elif score >= STORE_THRESHOLD:
        classification = "interesting"
    else:
        classification = "noise"

    return {
        "score": score,
        "total": N_CRIBS,
        "ene_score": ene_score,
        "bc_score": bc_score,
        "matched_positions": matched,
        "failed_positions": failed,
        "classification": classification,
    }


def is_above_noise(score: int) -> bool:
    """Is this score above the noise floor?"""
    return score > NOISE_FLOOR


def is_storable(score: int) -> bool:
    """Should this score be persisted?"""
    return score >= STORE_THRESHOLD


def is_signal(score: int) -> bool:
    """Is this score strong enough to investigate?"""
    return score >= SIGNAL_THRESHOLD


def is_breakthrough(score: int, bean_pass: bool = False) -> bool:
    """Is this a potential solution?"""
    return score >= BREAKTHROUGH_THRESHOLD and bean_pass
