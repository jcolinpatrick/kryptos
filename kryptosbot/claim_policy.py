"""
Policy gates for ProvenanceClaim downstream uses.

Every downstream consumer (critic, theory triage, prompt builder, summary
renderer) MUST route decisions about whether to use a claim as a hard
constraint, elimination basis, ranking feature, or prompt context through
these gates. Hand-written hedges in prose are NOT a substitute.

Each gate returns (allowed, reason). `reason` is always human-readable and
explains the restriction, even when `allowed` is True.
"""

from __future__ import annotations

from .provenance import (
    ProvenanceClaim,
    EpistemicClass as EC,
    AllowedUse as AU,
)


# Classes whose hard-constraint use depends on H1 context
_H1_CONDITIONAL_CLASSES = frozenset({
    EC.H1_CONDITIONAL_DERIVATION,
    EC.CONDITIONAL_ELIMINATION,
})

# Classes that can never be a hard constraint
_NEVER_HARD_CONSTRAINT = frozenset({
    EC.BEAN_REPORTED_NOT_RERUN,
    EC.INTERPRETIVE_PHYSICAL_OBSERVATION,
    EC.PROJECT_REVERIFIED_STATISTICAL_ANOMALY,
    EC.RETIRED_CLAIM,
    EC.HYPOTHESIS,
    EC.DISPROVED_HYPOTHESIS,
    EC.PHYSICAL_FACT,  # physical existence is not a cryptographic constraint
})

# Classes eligible for "must explain" promotion (most restrictive)
_MUST_EXPLAIN_ELIGIBLE = frozenset({
    EC.STRUCTURAL_ELIMINATION,
    EC.PUBLIC_FACT,
    EC.PRIMARY_SOURCE_FACT,
})


def _has_use(claim: ProvenanceClaim, use: AU) -> bool:
    return use in claim.allowed_downstream_uses


def can_use_as_hard_constraint(
    claim: ProvenanceClaim, h1_context: bool = False
) -> tuple[bool, str]:
    """May this claim be used as a kill criterion / contradiction check?"""
    if claim.epistemic_class == EC.RETIRED_CLAIM:
        return False, f"{claim.claim_id} is RETIRED; cannot be used as hard constraint"

    if claim.epistemic_class in _NEVER_HARD_CONSTRAINT:
        return (
            False,
            f"{claim.claim_id} is {claim.epistemic_class.value}; "
            f"never eligible to be a hard constraint (reported, interpretive, or statistical).",
        )

    if claim.epistemic_class in _H1_CONDITIONAL_CLASSES:
        if not h1_context:
            return (
                False,
                f"{claim.claim_id} is {claim.epistemic_class.value}; "
                f"hard-constraint use allowed only inside an explicit H1 workflow.",
            )
        if not _has_use(claim, AU.HARD_CONSTRAINT):
            return (
                False,
                f"{claim.claim_id} does not list HARD_CONSTRAINT in "
                f"allowed_downstream_uses; elimination-basis permission inside "
                f"H1 does not promote it to a hard constraint.",
            )
        return True, f"{claim.claim_id} allowed as hard constraint inside H1 context."

    if not _has_use(claim, AU.HARD_CONSTRAINT):
        return (
            False,
            f"{claim.claim_id} does not list HARD_CONSTRAINT in allowed_downstream_uses.",
        )
    return True, f"{claim.claim_id} allowed as hard constraint."


def can_use_as_elimination_basis(
    claim: ProvenanceClaim, h1_context: bool = False
) -> tuple[bool, str]:
    """May this claim be used as the basis for eliminating a theory?"""
    if claim.epistemic_class == EC.RETIRED_CLAIM:
        return False, f"{claim.claim_id} is RETIRED; cannot eliminate theories."

    if claim.epistemic_class in (
        EC.BEAN_REPORTED_NOT_RERUN,
        EC.INTERPRETIVE_PHYSICAL_OBSERVATION,
        EC.PROJECT_REVERIFIED_STATISTICAL_ANOMALY,
        EC.PHYSICAL_FACT,
    ):
        return (
            False,
            f"{claim.claim_id} is {claim.epistemic_class.value}; "
            f"cannot eliminate theories on this basis.",
        )

    if claim.epistemic_class in _H1_CONDITIONAL_CLASSES and not h1_context:
        return (
            False,
            f"{claim.claim_id} is {claim.epistemic_class.value}; "
            f"elimination-basis use allowed only inside an explicit H1 workflow.",
        )

    if not _has_use(claim, AU.ELIMINATION_BASIS):
        return (
            False,
            f"{claim.claim_id} does not list ELIMINATION_BASIS in allowed_downstream_uses.",
        )

    return True, f"{claim.claim_id} allowed as elimination basis."


def can_use_as_ranking_feature(claim: ProvenanceClaim) -> tuple[bool, str]:
    """May this claim be a soft signal in prioritization?"""
    if claim.epistemic_class == EC.RETIRED_CLAIM:
        return False, f"{claim.claim_id} is RETIRED; cannot rank by it."
    if not _has_use(claim, AU.RANKING_FEATURE):
        return (
            False,
            f"{claim.claim_id} does not list RANKING_FEATURE in allowed_downstream_uses.",
        )
    return True, f"{claim.claim_id} allowed as ranking feature."


def can_use_in_prompt(claim: ProvenanceClaim) -> tuple[bool, str]:
    """May this claim be injected into an agent prompt?"""
    if claim.epistemic_class == EC.RETIRED_CLAIM:
        # Retired claims can appear only as a 'do not revive' summary
        return (
            False,
            f"{claim.claim_id} is RETIRED; include only in retired-summary context.",
        )
    if not _has_use(claim, AU.PROMPT_CONTEXT):
        return (
            False,
            f"{claim.claim_id} does not list PROMPT_CONTEXT in allowed_downstream_uses.",
        )
    return True, f"{claim.claim_id} allowed in prompt context."


def can_promote_to_must_explain(claim: ProvenanceClaim) -> tuple[bool, str]:
    """May this claim be promoted to a 'theory must explain this' requirement?

    Most restrictive gate. Only structural eliminations and public/primary-source
    facts can become a must-explain constraint, and only if HARD_CONSTRAINT is
    in the claim's allowed_downstream_uses list.
    """
    if claim.epistemic_class not in _MUST_EXPLAIN_ELIGIBLE:
        return (
            False,
            f"{claim.claim_id} is {claim.epistemic_class.value}; "
            f"not eligible for must-explain promotion.",
        )
    if not _has_use(claim, AU.HARD_CONSTRAINT):
        return (
            False,
            f"{claim.claim_id} does not list HARD_CONSTRAINT; "
            f"cannot be promoted to must-explain.",
        )
    return True, f"{claim.claim_id} may be promoted to must-explain constraint."
