"""Two-layer stego + weak inner encipherment campaign (v1).

Tests one narrow architectural hypothesis:
    K4 = OUTER stego/masking/selection/projection/segmentation layer
       + INNER weak (near-identity-preserving) encipherment layer

Anti-overfitting principle: generation parameters and evaluation metrics
MUST NOT overlap. A candidate cannot pick its outer width by sweeping
all widths and choosing the best — that's post-hoc fit.
"""
from kryptos.campaigns.two_layer.families import (
    CompositionProfile,
    EvaluationResult,
    InnerFamily,
    InnerMixingClass,
    OuterFamily,
    ProvenanceClass,
)
from kryptos.campaigns.two_layer.provenance import ResultProvenance
from kryptos.campaigns.two_layer import outer_layers, inner_layers, evaluation, multiplicity

__all__ = [
    "CompositionProfile",
    "EvaluationResult",
    "InnerFamily",
    "InnerMixingClass",
    "OuterFamily",
    "ProvenanceClass",
    "ResultProvenance",
]
