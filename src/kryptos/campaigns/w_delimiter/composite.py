"""Transparent composite scoring with per-channel caps.

Design rule: no single channel may dominate the composite. Each feature's
contribution is capped so that a cheap win (e.g. new_zero_count) cannot
push a candidate into "interesting" territory alone.
"""
from __future__ import annotations

from typing import Dict, Optional

from kryptos.campaigns.w_delimiter.features import FeatureRecord


DEFAULT_WEIGHTS: Dict[str, float] = {
    "new_zero_count": 1.0,
    "new_equality_with_27_or_65": 3.0,
    "common_bigram_count": 0.5,
    "common_trigram_count": 1.5,
    "contains_known_keyword": 5.0,
    "semantic_coherence": 1.0,
    "complexity_penalty": -1.0,
}

# Per-channel caps: maximum absolute contribution each channel can add.
_CAPS: Dict[str, float] = {
    "new_zero_count": 3.0,                 # at most 3 points from this cheap channel
    "new_equality_with_27_or_65": 9.0,
    "common_bigram_count": 4.0,
    "common_trigram_count": 6.0,
    "contains_known_keyword": 5.0,
    "semantic_coherence": 1.0,
    "complexity_penalty": -3.0,
}


def _clip(value: float, cap: float) -> float:
    if cap >= 0:
        return min(value, cap)
    return max(value, cap)


def feature_breakdown(features: FeatureRecord, weights: Optional[Dict[str, float]] = None) -> Dict[str, float]:
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)
    raw = {
        "new_zero_count": w["new_zero_count"] * features.new_zero_count,
        "new_equality_with_27_or_65": w["new_equality_with_27_or_65"] * features.new_equality_with_27_or_65,
        "common_bigram_count": w["common_bigram_count"] * features.common_bigram_count,
        "common_trigram_count": w["common_trigram_count"] * features.common_trigram_count,
        "contains_known_keyword": w["contains_known_keyword"] * (1.0 if features.contains_known_keyword else 0.0),
        "semantic_coherence": w["semantic_coherence"] * features.semantic_coherence_score,
        "complexity_penalty": w["complexity_penalty"] * features.fill_complexity,
    }
    return {k: _clip(v, _CAPS[k]) for k, v in raw.items()}


def composite_score(features: FeatureRecord, weights: Optional[Dict[str, float]] = None) -> float:
    return sum(feature_breakdown(features, weights).values())
