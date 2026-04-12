"""Publication-grade elimination verdict rendering."""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List

from kryptos.campaigns.w_delimiter.distribution import CandidateRanking


@dataclass
class EliminationVerdict:
    verdict: str   # STRONG_ELIMINATION | NARROW_RESIDUAL | UNEXPECTED_HIT
    rationale: str
    candidates_in_tail: List[CandidateRanking]
    population_sizes: Dict[str, int]
    multiplicity_correction: str
    scope_caveats: List[str]
    publication_wording: str


_SCOPE_CAVEATS = [
    "This null does NOT cover segments 0, 2, 3, 5 (unconstrained under the cribs).",
    "This null only tests additive cipher variants (Vigenere, Beaufort, Variant Beaufort).",
    "This null assumes direct positional alignment CT[i] -> PT[i].",
    "This null does not rule out physical-overlay or procedural mechanisms outside the feature set.",
    "The W-delimiter hypothesis itself (H2) is treated as a working assumption, not as proven.",
]

_STRONG_TEMPLATE = (
    "Across the constrained English-plausible fill space for the W-delimiter "
    "model on Kryptos K4 (slot A: 2 chars after EASTNORTHEAST, slot B: 4 chars "
    "before BERLINCLOCK), tested under {n_pops} populations totaling {n_total} "
    "candidates with {n_features} feature channels under each of three "
    "additive cipher variants, no candidate produced a multi-channel tail event "
    "distinguishable from constrained combinatorics. The 'creates new "
    "self-encrypting position' finding is fully explained by P(letter match) "
    "under uniform sampling. The W-delimiter hypothesis class, restricted to "
    "additive cipher variants on the carved CT under direct positional "
    "alignment, is strongly disfavored within the testable scope. SCOPE: this "
    "null does not address (a) the unconstrained segments 0, 2, 3, 5; (b) "
    "non-additive ciphers; (c) physical-overlay or procedural mechanisms not "
    "expressible in the framework."
)


def render_verdict(
    rankings: List[CandidateRanking],
    populations: Dict[str, int],
    n_features: int = 7,
) -> EliminationVerdict:
    tail = [r for r in rankings if r.is_joint_tail]

    # Multiplicity correction: effective percentile after Bonferroni-style
    # adjustment against the total search size.
    total_searched = sum(populations.values())
    mult_log = math.log10(max(total_searched, 1))

    mult_text = (
        f"Total candidates evaluated across all populations: {total_searched}. "
        f"Any single-channel tail at percentile p needs p < 1/{total_searched:.0f} "
        f"(log10 = {mult_log:.2f}) to be genuinely rare. The joint-tail "
        "criterion requires multi-channel tail events in the grammatical "
        "population, which is a stricter bar than single-channel multiplicity."
    )

    n_pops = len(populations)
    pub_strong = _STRONG_TEMPLATE.format(
        n_pops=n_pops, n_total=total_searched, n_features=n_features,
    )

    if not tail:
        return EliminationVerdict(
            verdict="STRONG_ELIMINATION",
            rationale=(
                "No candidate in any population cleared the multi-channel "
                "joint-tail criterion. The top candidates by composite score "
                "are explainable by combinatorics of uniform fills, and no "
                "single-channel outlier survives multiplicity correction."
            ),
            candidates_in_tail=[],
            population_sizes=populations,
            multiplicity_correction=mult_text,
            scope_caveats=list(_SCOPE_CAVEATS),
            publication_wording=pub_strong,
        )

    # Surviving candidates exist. Check if any meets UNEXPECTED_HIT bar:
    # joint-tail in the CURATED population with multiplicity-aware
    # percentile < 0.001.
    curated_tail = [
        r for r in tail
        if r.candidate.source == "curated" and r.multiplicity_adjusted >= 0.999
    ]
    if curated_tail:
        lines = ["Candidates that cleared joint-tail + curated + multiplicity:"]
        for r in curated_tail:
            lines.append(
                f"  - A='{r.candidate.slot_a_pt}' B='{r.candidate.slot_b_pt}' "
                f"variant={r.raw_features.variant} composite={r.composite:.2f} "
                f"mult_adj={r.multiplicity_adjusted:.4f}"
            )
        lines.append(
            "These require replication from a fresh interpreter and a "
            "pre-registered follow-up test before any claim is made."
        )
        return EliminationVerdict(
            verdict="UNEXPECTED_HIT",
            rationale="\n".join(lines),
            candidates_in_tail=curated_tail,
            population_sizes=populations,
            multiplicity_correction=mult_text,
            scope_caveats=list(_SCOPE_CAVEATS),
            publication_wording=(
                "One or more candidates survived the multi-channel joint-tail "
                "criterion AND multiplicity correction within the curated "
                "population. This is a candidate for replication, not a claim. "
                "See candidate list. Scope caveats still apply; the surviving "
                "tail only addresses slots A and B under additive ciphers."
            ),
        )

    # Narrow residual
    lines = ["Candidates that cleared joint-tail but NOT curated+multiplicity:"]
    for r in tail[:20]:
        lines.append(
            f"  - A='{r.candidate.slot_a_pt}' B='{r.candidate.slot_b_pt}' "
            f"src={r.candidate.source} variant={r.raw_features.variant} "
            f"composite={r.composite:.2f}"
        )
    return EliminationVerdict(
        verdict="NARROW_RESIDUAL",
        rationale="\n".join(lines),
        candidates_in_tail=tail,
        population_sizes=populations,
        multiplicity_correction=mult_text,
        scope_caveats=list(_SCOPE_CAVEATS),
        publication_wording=(
            "A narrow residual tail survives the multi-channel joint-tail "
            "criterion but does not clear multiplicity-corrected "
            "curated-population bar. The W-delimiter hypothesis is not "
            "eliminated within these narrow surviving cells; each listed "
            "candidate requires an independent follow-up test before any "
            "further claim. Scope caveats apply."
        ),
    )
