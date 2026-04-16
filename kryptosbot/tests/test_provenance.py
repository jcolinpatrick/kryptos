"""
Tests for the provenance / epistemic-status layer.

Covers:
- Canonical claims load and validate
- Auto-hedge rendering for each EpistemicClass
- Policy gates (hard constraint / elimination basis / must explain)
- Scope-based hedges (crib position scope, Beaufort A=0, external statistic)
- Retired claims blocked from use
- H1-context gating of H1_CONDITIONAL_DERIVATION
- Dependency chain integrity
- Inventory generation groups by class
- Backward compatibility: old ledger DBs without claims table still work
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.provenance import (
    ProvenanceClaim,
    ScopeConditions,
    EpistemicClass,
    VerificationStatus,
    ReproducibilityStatus,
    AllowedUse,
)
from kryptosbot.claims_registry import (
    CANONICAL_CLAIMS,
    CANONICAL_CLAIMS_BY_ID,
    get_canonical_claim,
)
from kryptosbot.claim_rendering import (
    render_claim,
    render_claim_inline,
    render_inventory,
)
from kryptosbot.claim_policy import (
    can_use_as_hard_constraint,
    can_use_as_elimination_basis,
    can_use_as_ranking_feature,
    can_use_in_prompt,
    can_promote_to_must_explain,
)
from kryptosbot.theory_ledger import TheoryLedger
from kryptosbot.models import TheoryRecord, TheoryStatus


# ---------------------------------------------------------------------------
# Rendering tests
# ---------------------------------------------------------------------------


def test_h1_conditional_renders_with_hedge():
    claim = CANONICAL_CLAIMS_BY_ID["bean_equality"]
    text = render_claim_inline(claim)
    assert "Under H1" in text


def test_bean_reported_renders_as_not_rerun():
    claim = CANONICAL_CLAIMS_BY_ID["bean_minor_diffs"]
    text = render_claim_inline(claim)
    assert "not independently re-derived" in text.lower()


def test_624_renders_as_crib_position_only():
    claim = CANONICAL_CLAIMS_BY_ID["bean_624_keystream_vectors"]
    text = render_claim_inline(claim)
    assert "24 crib positions" in text


def test_beaufort_a0_scope_phrase_injected():
    claim = CANONICAL_CLAIMS_BY_ID["beaufort_a0_crib_keystream"]
    text = render_claim_inline(claim)
    assert "Beaufort A=0" in text


def test_structural_vs_conditional_elimination_distinguished():
    structural = CANONICAL_CLAIMS_BY_ID["pure_transposition_impossible"]
    conditional = CANONICAL_CLAIMS_BY_ID["periodic_poly_eliminated_h1"]
    s_text = render_claim_inline(structural)
    c_text = render_claim_inline(conditional)
    assert "Under H1" not in s_text  # structural has no H1 hedge
    assert "Elimination scope" in c_text


def test_retired_claim_renders_with_retired_banner():
    claim = CANONICAL_CLAIMS_BY_ID["null_palette_retired"]
    text = render_claim_inline(claim)
    assert "[RETIRED]" in text
    assert "Do not revive" in text


def test_rendering_is_idempotent():
    claim = CANONICAL_CLAIMS_BY_ID["bean_equality"]
    once = render_claim_inline(claim)
    # Build a claim with claim_text = once and re-render — should not stack.
    replay = ProvenanceClaim(
        claim_id="replay",
        claim_text=once,
        epistemic_class=EpistemicClass.H1_CONDITIONAL_DERIVATION,
        scope_conditions=claim.scope_conditions,
    )
    twice = render_claim_inline(replay)
    assert twice.count("Under H1") == 1


# ---------------------------------------------------------------------------
# Policy gate tests
# ---------------------------------------------------------------------------


def test_physical_anomaly_not_auto_constraint():
    claim = CANONICAL_CLAIMS_BY_ID["yar_physical_existence"]
    ok, _ = can_use_as_hard_constraint(claim)
    assert ok is False


def test_interpretation_cannot_eliminate_theories():
    claim = CANONICAL_CLAIMS_BY_ID["yar_cryptographic_interpretation"]
    ok, _ = can_use_as_elimination_basis(claim)
    assert ok is False


def test_bean_reported_not_promoted_to_must_explain():
    claim = CANONICAL_CLAIMS_BY_ID["bean_minor_diffs"]
    ok, _ = can_promote_to_must_explain(claim)
    assert ok is False


def test_bean_reported_allowed_as_ranking_feature():
    claim = CANONICAL_CLAIMS_BY_ID["bean_minor_diffs"]
    ok, _ = can_use_as_ranking_feature(claim)
    assert ok is True


def test_retired_palette_blocked_from_all_uses_except_summary():
    claim = CANONICAL_CLAIMS_BY_ID["null_palette_retired"]
    assert can_use_as_hard_constraint(claim)[0] is False
    assert can_use_as_elimination_basis(claim)[0] is False
    assert can_use_as_ranking_feature(claim)[0] is False
    assert can_use_in_prompt(claim)[0] is False
    assert can_promote_to_must_explain(claim)[0] is False


def test_h1_conditional_allowed_in_h1_context():
    claim = CANONICAL_CLAIMS_BY_ID["bean_equality"]
    # Without H1 context: blocked
    assert can_use_as_elimination_basis(claim, h1_context=False)[0] is False
    # With H1 context: permitted (it lists ELIMINATION_BASIS)
    assert can_use_as_elimination_basis(claim, h1_context=True)[0] is True


def test_h1_elimination_basis_not_promoted_to_hard_constraint():
    claim = CANONICAL_CLAIMS_BY_ID["bean_equality"]
    ok, reason = can_use_as_hard_constraint(claim, h1_context=True)
    assert ok is False
    assert "does not list HARD_CONSTRAINT" in reason


def test_project_anomaly_cannot_eliminate():
    claim = CANONICAL_CLAIMS_BY_ID["width21_bigrams"]
    ok, _ = can_use_as_elimination_basis(claim)
    assert ok is False


def test_structural_elimination_promotable_to_must_explain():
    claim = CANONICAL_CLAIMS_BY_ID["pure_transposition_impossible"]
    ok, _ = can_promote_to_must_explain(claim)
    assert ok is True


# ---------------------------------------------------------------------------
# Registry integrity
# ---------------------------------------------------------------------------


def test_canonical_claims_load_without_errors():
    assert len(CANONICAL_CLAIMS) > 20
    for c in CANONICAL_CLAIMS:
        assert isinstance(c.epistemic_class, EpistemicClass)
        assert isinstance(c.verification_status, VerificationStatus)
        assert isinstance(c.reproducibility_status, ReproducibilityStatus)
        assert c.claim_id
        # Roundtrip to_dict/from_dict
        d = c.to_dict()
        c2 = ProvenanceClaim.from_dict(d)
        assert c2.claim_id == c.claim_id
        assert c2.epistemic_class == c.epistemic_class


def test_claim_dependency_chain_resolves():
    linear = CANONICAL_CLAIMS_BY_ID["bean_linear_101"]
    assert "bean_inequalities_242" in linear.dependency_chain
    ineq = CANONICAL_CLAIMS_BY_ID["bean_inequalities_242"]
    assert "bean_equality" in ineq.dependency_chain
    eq = CANONICAL_CLAIMS_BY_ID["bean_equality"]
    assert "k4_ct_97char" in eq.dependency_chain


def test_bean_624_scoped_to_crib_positions():
    claim = CANONICAL_CLAIMS_BY_ID["bean_624_keystream_vectors"]
    assert claim.scope_conditions.applies_only_to_crib_positions is True
    assert claim.scope_conditions.assumes_direct_positional_crib_alignment is True


def test_physical_anomalies_split_existence_vs_interpretation():
    # YAR
    existence = CANONICAL_CLAIMS_BY_ID["yar_physical_existence"]
    interp = CANONICAL_CLAIMS_BY_ID["yar_cryptographic_interpretation"]
    assert existence.epistemic_class == EpistemicClass.PHYSICAL_FACT
    assert interp.epistemic_class == EpistemicClass.INTERPRETIVE_PHYSICAL_OBSERVATION
    assert "yar_physical_existence" in interp.dependency_chain


# ---------------------------------------------------------------------------
# Inventory generation
# ---------------------------------------------------------------------------


def test_inventory_generation_groups_by_class():
    out = render_inventory(CANONICAL_CLAIMS)
    assert "# Provenance inventory" in out
    assert "## H1-conditional derivations" in out
    assert "## Bean-reported" in out
    assert "## Retired claims" in out
    assert "## Summary" in out


def test_inventory_does_not_emit_must_explain_language():
    out = render_inventory(CANONICAL_CLAIMS)
    # Red-team invariant: inventory must never frame Bean-reported or
    # statistical anomalies as things a theory "must explain".
    lower = out.lower()
    assert "must explain all three" not in lower
    assert "mandatory constraint" not in lower or "not a mandatory" in lower


# ---------------------------------------------------------------------------
# Ledger integration + backward compatibility
# ---------------------------------------------------------------------------


def test_backward_compat_old_ledger_no_claims_bootstrap():
    """A fresh ledger not seeded with claims still supports theories CRUD."""
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "t.sqlite"
        ledger = TheoryLedger(db)
        # Theories CRUD must still work even though no claims were bootstrapped
        theory = TheoryRecord(
            hypothesis_id="h-test",
            title="test",
            core_claim="a claim",
            mechanism="a mechanism",
            family="vigenere",
            status=TheoryStatus.PROPOSED,
        )
        ledger.upsert_theory(theory)
        assert ledger.get_theory("h-test") is not None
        # And get_all_claims returns [] cleanly
        assert ledger.get_all_claims() == []


def test_ledger_upsert_and_roundtrip_claim():
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "t.sqlite"
        ledger = TheoryLedger(db)
        sample = CANONICAL_CLAIMS_BY_ID["bean_equality"]
        ledger.upsert_claim(sample)
        fetched = ledger.get_claim("bean_equality")
        assert fetched is not None
        assert fetched.epistemic_class == EpistemicClass.H1_CONDITIONAL_DERIVATION
        assert fetched.scope_conditions.assumes_direct_positional_crib_alignment is True


def test_bootstrap_claims_populates_ledger():
    from kryptosbot.registries import bootstrap_claims
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "t.sqlite"
        ledger = TheoryLedger(db)
        n = bootstrap_claims(ledger)
        assert n == len(CANONICAL_CLAIMS)
        assert len(ledger.get_all_claims()) == n
        by_class = ledger.get_claims_by_class(EpistemicClass.RETIRED_CLAIM)
        assert any(c.claim_id == "null_palette_retired" for c in by_class)
