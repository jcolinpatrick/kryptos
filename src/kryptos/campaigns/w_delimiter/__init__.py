"""W-delimiter null elimination campaign (v1).

Tests ONE narrow architectural hypothesis:
    The letter W in K4 ciphertext acts as a delimiter (or null),
    segmenting K4 into 6 runs at positions {20, 36, 48, 58, 74}.

The campaign is a disciplined distributional null test over the
CONSTRAINED fill slots created by the cribs:

    Slot A: positions 34-35  (after EASTNORTHEAST, before W[36]), 2 chars
    Slot B: positions 59-62  (after W[58], before BERLINCLOCK),   4 chars

All other segments (0, 2, 3, 5) are UNCONSTRAINED under current cribs and
are NOT covered by this null. The framework explicitly discloses that
scope limit in every verdict.

Anti-overfitting principle: no single feature channel (especially
"new self-encrypting positions") may drive the verdict. A candidate must
survive a multi-channel joint-tail criterion AND multiplicity correction.
"""
from kryptos.campaigns.w_delimiter.slot_model import (
    WDelimiterSlot,
    WDelimiterModel,
    canonical_w_delimiter_model,
)
from kryptos.campaigns.w_delimiter.populations import (
    FillCandidate,
    population_random,
    population_dictionary,
    population_grammatical_fit,
    population_curated_best,
)
from kryptos.campaigns.w_delimiter.features import (
    FeatureRecord,
    compute_features,
)
from kryptos.campaigns.w_delimiter.composite import (
    DEFAULT_WEIGHTS,
    composite_score,
    feature_breakdown,
)
from kryptos.campaigns.w_delimiter.distribution import (
    FeatureDistribution,
    CandidateRanking,
    compute_distribution,
    percentile_of,
    fraction_at_or_above,
)
from kryptos.campaigns.w_delimiter.elimination import (
    EliminationVerdict,
    render_verdict,
)

__all__ = [
    "WDelimiterSlot",
    "WDelimiterModel",
    "canonical_w_delimiter_model",
    "FillCandidate",
    "population_random",
    "population_dictionary",
    "population_grammatical_fit",
    "population_curated_best",
    "FeatureRecord",
    "compute_features",
    "DEFAULT_WEIGHTS",
    "composite_score",
    "feature_breakdown",
    "FeatureDistribution",
    "CandidateRanking",
    "compute_distribution",
    "percentile_of",
    "fraction_at_or_above",
    "EliminationVerdict",
    "render_verdict",
]
