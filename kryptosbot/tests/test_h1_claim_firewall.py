"""Suite-assurance Task A — H1 claim firewall.

Pins the assumption firewall: H1-conditional claims (Bean derivations,
direct-positional eliminations) may NEVER act as an elimination basis or
hard constraint outside an explicit H1 workflow context. The critic's
claim gate (`_claim_permits_elimination`) is the enforcement chokepoint —
if a future change starts passing ``h1_context=True`` unconditionally (or
defaults it on), every registered H1-conditional / conditional-elimination
claim would silently become a global kill rule, and these tests fail.

This is a behavioral pin over the FULL registry, not a sample: any newly
registered H1-conditional claim is automatically covered.
"""
from __future__ import annotations

from kryptosbot.claims_registry import CANONICAL_CLAIMS
from kryptosbot.claim_policy import (
    can_use_as_elimination_basis,
    can_use_as_hard_constraint,
)
from kryptosbot.critic import TheoryCritic
from kryptosbot.provenance import AllowedUse, EpistemicClass

_H1_CLASSES = (
    EpistemicClass.H1_CONDITIONAL_DERIVATION,
    EpistemicClass.CONDITIONAL_ELIMINATION,
)


def _h1_claims():
    claims = [c for c in CANONICAL_CLAIMS if c.epistemic_class in _H1_CLASSES]
    assert claims, "registry no longer holds any H1-conditional claims?"
    return claims


def test_no_h1_claim_is_elimination_basis_outside_h1_context():
    for claim in _h1_claims():
        allowed, reason = can_use_as_elimination_basis(claim, h1_context=False)
        assert allowed is False, (
            f"{claim.claim_id} ({claim.epistemic_class}) usable as an "
            f"elimination basis WITHOUT H1 context: {reason}"
        )


def test_no_h1_claim_is_hard_constraint_outside_h1_context():
    for claim in _h1_claims():
        allowed, reason = can_use_as_hard_constraint(claim, h1_context=False)
        assert allowed is False, (
            f"{claim.claim_id} ({claim.epistemic_class}) usable as a hard "
            f"constraint WITHOUT H1 context: {reason}"
        )


def test_critic_gate_refuses_all_h1_claims_by_default():
    """The critic's chokepoint, exactly as the contradiction path calls it
    (no h1_context argument). A dummy instance suffices — the helper only
    reads the registry and the policy gates."""
    critic = object.__new__(TheoryCritic)
    for claim in _h1_claims():
        assert TheoryCritic._claim_permits_elimination(critic, claim.claim_id) is False, (
            f"critic gate permits H1-conditional claim {claim.claim_id} as a "
            "kill rule without explicit H1 context"
        )


def test_h1_gate_direction_positive_control():
    """With explicit H1 context, claims whitelisted for ELIMINATION_BASIS
    are permitted — proving the gate tests above are not vacuously False."""
    permitted = [
        c for c in _h1_claims()
        if AllowedUse.ELIMINATION_BASIS in c.allowed_downstream_uses
        and can_use_as_elimination_basis(c, h1_context=True)[0]
    ]
    assert permitted, (
        "no H1-conditional claim is permitted even WITH h1_context=True — "
        "the firewall tests would be vacuous"
    )
