"""Distributional analysis and per-candidate ranking."""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from kryptos.campaigns.w_delimiter.features import FeatureRecord
from kryptos.campaigns.w_delimiter.populations import FillCandidate


_NUMERIC_FEATURES = (
    "new_zero_count",
    "new_equality_pairs",
    "new_equality_with_27_or_65",
    "distinct_letters",
    "max_run_length",
    "common_bigram_count",
    "common_trigram_count",
    "semantic_coherence_score",
    "fill_complexity",
)


def _get_feature(rec: FeatureRecord, name: str) -> float:
    val = getattr(rec, name)
    if isinstance(val, bool):
        return 1.0 if val else 0.0
    return float(val)


@dataclass
class FeatureDistribution:
    feature_name: str
    population_name: str
    n: int
    histogram: Dict[float, int]
    quantiles: Dict[float, float]
    mean: float
    std: float


def _quantile(sorted_vals: List[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    if q <= 0:
        return sorted_vals[0]
    if q >= 1:
        return sorted_vals[-1]
    idx = q * (len(sorted_vals) - 1)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return sorted_vals[lo]
    frac = idx - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def compute_distribution(records: List[FeatureRecord], feature_name: str, population_name: str) -> FeatureDistribution:
    if not records:
        return FeatureDistribution(feature_name, population_name, 0, {}, {}, 0.0, 0.0)
    vals = [_get_feature(r, feature_name) for r in records]
    n = len(vals)
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n
    std = math.sqrt(var)
    hist: Dict[float, int] = dict(Counter(vals))
    svals = sorted(vals)
    quantiles = {
        0.5: _quantile(svals, 0.5),
        0.9: _quantile(svals, 0.9),
        0.95: _quantile(svals, 0.95),
        0.99: _quantile(svals, 0.99),
        0.999: _quantile(svals, 0.999),
    }
    return FeatureDistribution(feature_name, population_name, n, hist, quantiles, mean, std)


def percentile_of(value: float, distribution: FeatureDistribution) -> float:
    """Fraction of the distribution strictly less than `value`, in [0,1].

    A percentile of 0.99 means this value is greater than 99% of the population.
    """
    if distribution.n == 0:
        return 0.0
    below = 0
    for v, c in distribution.histogram.items():
        if v < value:
            below += c
    return below / distribution.n


def fraction_at_or_above(value: float, distribution: FeatureDistribution) -> float:
    if distribution.n == 0:
        return 1.0
    above = 0
    for v, c in distribution.histogram.items():
        if v >= value:
            above += c
    return above / distribution.n


@dataclass
class CandidateRanking:
    candidate: FillCandidate
    raw_features: FeatureRecord
    composite: float
    feature_breakdown: Dict[str, float]
    percentile_in_random: Dict[str, float] = field(default_factory=dict)
    percentile_in_dictionary: Dict[str, float] = field(default_factory=dict)
    percentile_in_grammatical: Dict[str, float] = field(default_factory=dict)
    percentile_in_curated: Dict[str, float] = field(default_factory=dict)
    multiplicity_adjusted: float = 0.0
    is_joint_tail: bool = False


def compute_joint_tail(
    rank: CandidateRanking,
    grammatical_distributions: Dict[str, FeatureDistribution],
    tail_threshold: float = 0.99,
    min_channels: int = 2,
) -> bool:
    """Joint-tail criterion: top 1% on >=2 distinct feature channels,
    measured against the GRAMMATICAL population."""
    channels_in_tail = 0
    for feat_name, dist in grammatical_distributions.items():
        val = _get_feature(rank.raw_features, feat_name)
        pct = percentile_of(val, dist)
        if pct >= tail_threshold:
            channels_in_tail += 1
    return channels_in_tail >= min_channels
