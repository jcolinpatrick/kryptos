"""Provenance-gated, bounded, two-tier mask hypotheses.

Mirrors the disproof-protocol / dispatcher-dsl-contract discipline: a mask
search is admissible only as a bounded, hashed universe with a declared
alignment model and (for primary tier) a provenance artifact. Exploratory
masks are allowed but quarantined and never promotable to a global K4 fact.
The alignment_model keys match the session-briefing assumption-boundary taxonomy.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import FrozenSet, Literal, Tuple

ALIGNMENT_MODEL_KEYS: FrozenSet[str] = frozenset({
    "direct_ct_pt", "fixed_len_97", "ct73_null_extracted",
    "arbitrary_null_mask", "non_direct_alignment", "joint_mask_mechanism",
})

Tier = Literal["primary_evidentiary", "secondary_exploratory"]


@dataclass(frozen=True)
class MaskUniverse:
    masks: Tuple[FrozenSet[int], ...]
    description: str

    @property
    def universe_hash(self) -> str:
        payload = "|".join(
            ",".join(str(p) for p in sorted(m)) for m in self.masks
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MaskHypothesis:
    mask_universe: MaskUniverse
    alignment_model: str
    provenance: str
    assumption_bundle: Tuple[str, ...]
    tier: Tier
    stop_rule: str


def validate_mask_hypothesis(h: MaskHypothesis) -> list[str]:
    """Return a list of admissibility errors (empty == admissible)."""
    errors: list[str] = []
    if h.alignment_model not in ALIGNMENT_MODEL_KEYS:
        errors.append(f"unknown alignment_model {h.alignment_model!r}")
    if not h.mask_universe.masks:
        errors.append("mask_universe is empty (no bounded universe)")
    if not h.stop_rule:
        errors.append("missing stop_rule")
    if h.tier == "primary_evidentiary" and not h.provenance.strip():
        errors.append("primary_evidentiary tier requires a provenance artifact")
    if h.tier not in ("primary_evidentiary", "secondary_exploratory"):
        errors.append(f"unknown tier {h.tier!r}")
    return errors
