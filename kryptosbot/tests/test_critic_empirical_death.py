"""Tests for TheoryCritic._check_family_empirically_dead.

Eight branches: dead/healthy x bypass-eligible/ineligible x normal/shadow.
"""
from __future__ import annotations

from kryptosbot.critic import TheoryCritic
from kryptosbot.family_yield import (
    FamilyYieldPolicy,
    FamilyYieldStats,
    FamilyYieldVerdict,
)
from kryptosbot.models import (
    CriticDecision,
    TheoryRecord,
    TheoryStatus,
)


def _verdict(family, status="empirically_dead", n=826, mean=0.78, best=7.0):
    stats = FamilyYieldStats(family, n, mean, best, 0, n - 1)
    return FamilyYieldVerdict(family, status, ("r",), stats)


def _theory(
    family="encoding",
    subfamily="brand_new_subfamily",
    dsl_spec=None,
    mechanism="m",
):
    return TheoryRecord(
        hypothesis_id="hid_test",
        title="t", core_claim="c", mechanism=mechanism,
        family=family, subfamily=subfamily,
        status=TheoryStatus.PROPOSED,
        dsl_spec=dsl_spec,
    )


class FakeLedger:
    """Minimal ledger stub that the critic uses only via attribute access."""
    def get_family(self, *_): return None


def _critic_with_indices(yield_idx, prior_subfams, prior_sigs, policy=None):
    c = TheoryCritic(ledger=FakeLedger())
    c.yield_index = yield_idx
    c.prior_subfamilies = prior_subfams
    c.prior_signatures = prior_sigs
    c.policy = policy or FamilyYieldPolicy()
    return c


class TestCheckFamilyEmpiricallyDead:

    def test_healthy_family_returns_none(self):
        c = _critic_with_indices(
            yield_idx={"healthy_fam": _verdict("healthy_fam", "healthy")},
            prior_subfams={}, prior_sigs={},
        )
        t = _theory(family="healthy_fam")
        result = c._check_family_empirically_dead(t, "healthy_fam")
        assert result is None

    def test_family_not_in_index_returns_none(self):
        c = _critic_with_indices(yield_idx={}, prior_subfams={}, prior_sigs={})
        t = _theory(family="encoding")
        assert c._check_family_empirically_dead(t, "encoding") is None

    def test_dead_no_bypass_returns_reject(self):
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"vigenere"})},
            prior_sigs={"encoding": frozenset(["sig_known"])},
        )
        # Subfamily already known; mechanism_signature also computed from
        # _theory's empty dsl_spec is the Category-B signature, which we
        # also seed into prior_sigs via the same compute path.
        from kryptosbot.family_yield import mechanism_signature_for_theory
        t = _theory(family="encoding", subfamily="vigenere", mechanism="m")
        sig = mechanism_signature_for_theory({
            "family": "encoding", "subfamily": "vigenere",
            "mechanism": "m", "dsl_spec": None,
            "anomalies_exploited": [], "clue_anchors_used": [],
            "novelty_basis": "", "minimal_test_spec": {},
        })
        c.prior_signatures = {"encoding": frozenset([sig])}

        verdict = c._check_family_empirically_dead(t, "encoding")
        assert verdict is not None
        assert verdict.decision == CriticDecision.REJECT_EMPIRICALLY_DEAD
        assert verdict.empirical_death is not None
        assert verdict.empirical_death.family == "encoding"

    def test_dead_bypass_eligible_returns_none(self):
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"old_subfam"})},
            prior_sigs={"encoding": frozenset({"sig_other"})},
        )
        t = _theory(family="encoding", subfamily="brand_new_subfamily")
        assert c._check_family_empirically_dead(t, "encoding") is None

    def test_shadow_mode_logs_but_returns_none(self, caplog):
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"vigenere"})},
            prior_sigs={"encoding": frozenset({"sig_dummy"})},
            policy=FamilyYieldPolicy(shadow_mode=True),
        )
        # Make the theory ineligible so the gate WOULD fire.
        t = _theory(family="encoding", subfamily="vigenere", mechanism="m")
        result = c._check_family_empirically_dead(t, "encoding")
        assert result is None
        assert "shadow" in caplog.text.lower() or "would_reject" in caplog.text.lower()

    def test_low_yield_status_does_not_reject(self):
        c = _critic_with_indices(
            yield_idx={"grille": _verdict("grille", status="low_yield")},
            prior_subfams={"grille": frozenset({"spiral"})},
            prior_sigs={"grille": frozenset({"sig"})},
        )
        t = _theory(family="grille", subfamily="spiral")
        assert c._check_family_empirically_dead(t, "grille") is None

    def test_payload_includes_failed_reasons(self):
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"vigenere"})},
            prior_sigs={"encoding": frozenset({"sig_known"})},
        )
        t = _theory(family="encoding", subfamily="vigenere")
        verdict = c._check_family_empirically_dead(t, "encoding")
        assert verdict is not None
        assert verdict.empirical_death is not None
        assert len(verdict.empirical_death.bypass_failed_reasons) >= 1

    def test_suggested_mechanisms_empty_in_phase_1(self):
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"vigenere"})},
            prior_sigs={"encoding": frozenset({"sig_known"})},
        )
        t = _theory(family="encoding", subfamily="vigenere")
        verdict = c._check_family_empirically_dead(t, "encoding")
        assert verdict.empirical_death.suggested_mechanisms == ()


class TestCriticOrdering:
    """Empirical-death goes AFTER tier-1/tier-2 and AFTER duplicate detection,
    but BEFORE contradiction and DSL-translatability."""

    def test_tier_1_wins_over_empirical_death(self):
        from kryptosbot.critic import TheoryCritic, TIER_1_FAMILIES
        # Pick a family that's BOTH Tier-1 AND empirically_dead in our index.
        tier_1_family = next(iter(TIER_1_FAMILIES))
        c = TheoryCritic(ledger=FakeLedger())
        c.yield_index = {tier_1_family: _verdict(tier_1_family)}
        c.prior_subfamilies = {tier_1_family: frozenset({"old"})}
        c.prior_signatures = {tier_1_family: frozenset({"sig_known"})}
        t = TheoryRecord(
            hypothesis_id="hid_tier1",
            title="t", core_claim="c", mechanism="m",
            family=tier_1_family, subfamily="old",
            status=TheoryStatus.PROPOSED,
        )
        verdict = c.evaluate(t)
        # Tier-1 wins. The verdict reason mentions Tier-1, not empirically-dead.
        assert verdict.decision == CriticDecision.REJECT_ELIMINATED
        assert verdict.empirical_death is None

    def test_duplicate_wins_over_empirical_death(self):
        # A theory that is a duplicate of an existing one in a dead family
        # must get REJECT_DUPLICATE, not REJECT_EMPIRICALLY_DEAD.
        # Setup: build a ledger with an existing 'encoding' theory and a
        # second proposal with the same hypothesis_id / dsl_spec.
        # (Specific implementation depends on existing duplicate-detection;
        # the assertion is that ordering puts duplicate first.)
        from kryptosbot.theory_ledger import TheoryLedger
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as tmpd:
            ledger = TheoryLedger(pathlib.Path(tmpd) / "l.sqlite")
            existing = TheoryRecord(
                hypothesis_id="hid_existing",
                title="t", core_claim="c", mechanism="vig",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.ELIMINATED,
                dsl_spec={"layers": [{"kind": "vigenere", "keyword": "X"}]},
            )
            ledger.upsert_theory(existing)

            c = TheoryCritic(ledger=ledger)
            c.yield_index = {"encoding": _verdict("encoding")}
            c.prior_subfamilies = {"encoding": frozenset({"vigenere"})}
            c.prior_signatures = {"encoding": frozenset({"sig_dummy"})}

            duplicate = TheoryRecord(
                hypothesis_id="hid_new",  # different id
                title="t", core_claim="c", mechanism="vig",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.PROPOSED,
                dsl_spec={"layers": [{"kind": "vigenere", "keyword": "X"}]},
            )
            verdict = c.evaluate(duplicate)
            assert verdict.decision == CriticDecision.REJECT_DUPLICATE
