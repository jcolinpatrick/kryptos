"""Tests for kryptosbot/family_yield.py: pure policy module."""
from __future__ import annotations

import pytest

from kryptosbot.family_yield import (
    DEFAULT_POLICY,
    FamilyYieldPolicy,
    FamilyYieldStats,
    FamilyYieldVerdict,
    check_bypass_eligibility,
    classify_family_yield,
)


class TestDataclasses:
    def test_policy_defaults(self):
        p = FamilyYieldPolicy()
        assert p.min_trials == 50
        assert p.mean_score_below == 2.0
        assert p.require_zero_promotions is True
        assert p.require_best_below_store_threshold is True
        assert p.low_yield_trials == 50
        assert p.low_yield_mean_below == 2.0
        assert p.shadow_mode is False

    def test_policy_is_frozen(self):
        p = FamilyYieldPolicy()
        with pytest.raises((AttributeError, Exception)):
            p.min_trials = 999

    def test_default_policy_singleton(self):
        assert DEFAULT_POLICY == FamilyYieldPolicy()

    def test_stats_shape(self):
        s = FamilyYieldStats(
            family="encoding",
            trials=826,
            mean_score=0.78,
            best_score=7.0,
            promotions=0,
            eliminated=750,
        )
        assert s.family == "encoding"
        assert s.trials == 826

    def test_verdict_shape(self):
        s = FamilyYieldStats("x", 1, 0.0, 0.0, 0, 0)
        v = FamilyYieldVerdict(
            family="x",
            status="healthy",
            reasons=("ok",),
            stats=s,
        )
        assert v.status == "healthy"
        assert v.stats is s


def _stats(family="x", trials=100, mean=0.5, best=0.0, promotions=0, eliminated=0):
    return FamilyYieldStats(family, trials, mean, best, promotions, eliminated)


class TestClassifyFamilyYield:
    def test_insufficient_data_when_below_min_trials(self):
        s = _stats(trials=49, mean=0.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "insufficient_data"

    def test_boundary_min_trials_49_not_dead(self):
        # n=49 with same metrics that WOULD be dead at n=50 must stay healthy.
        s = _stats(trials=49, mean=0.5, best=5.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "insufficient_data"

    def test_boundary_min_trials_50_can_be_dead(self):
        s = _stats(trials=50, mean=0.5, best=5.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "empirically_dead"

    def test_empirically_dead_full_match(self):
        # The 4 audit families.
        s = _stats(family="encoding", trials=826, mean=0.78, best=7.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "empirically_dead"
        assert "n=826" in " ".join(v.reasons)

    def test_low_yield_when_mean_low_but_best_at_or_above_store(self):
        # best_score >= STORE_THRESHOLD (10) blocks empirically_dead; falls
        # back to low_yield because mean is still under the low_yield threshold.
        s = _stats(trials=200, mean=1.0, best=12.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "low_yield"

    def test_healthy_when_promotions_present(self):
        s = _stats(trials=200, mean=0.5, best=5.0, promotions=1)
        v = classify_family_yield(s)
        assert v.status == "healthy"

    def test_healthy_when_mean_above_low_yield_threshold(self):
        s = _stats(trials=200, mean=3.0, best=5.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "healthy"

    def test_classifier_is_deterministic_for_same_inputs(self):
        s = _stats(trials=100, mean=0.5, best=5.0, promotions=0)
        a = classify_family_yield(s)
        b = classify_family_yield(s)
        assert a == b


class TestCheckBypassEligibility:
    def test_eligible_when_both_subfamily_and_signature_are_new(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="new_subfamily_v1",
            mechanism_signature="sig_abc",
            prior_subfamilies_in_family=frozenset({"old1", "old2"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is True
        assert reasons == ()

    def test_ineligible_when_subfamily_already_tried(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="old1",
            mechanism_signature="sig_abc",
            prior_subfamilies_in_family=frozenset({"old1"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is False
        assert any("subfamily" in r.lower() for r in reasons)

    def test_ineligible_when_signature_already_tried(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="new_subfamily_v1",
            mechanism_signature="sig_old",
            prior_subfamilies_in_family=frozenset({"old1"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is False
        assert any("signature" in r.lower() for r in reasons)

    def test_ineligible_when_both_already_tried(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="old1",
            mechanism_signature="sig_old",
            prior_subfamilies_in_family=frozenset({"old1"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is False
        assert len(reasons) == 2

    def test_subfamily_empty_string_is_ineligible(self):
        # Empty subfamily cannot prove structural novelty.
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="",
            mechanism_signature="sig_new",
            prior_subfamilies_in_family=frozenset(),
            prior_mechanism_signatures_in_family=frozenset(),
        )
        assert eligible is False
        assert any("empty subfamily" in r.lower() for r in reasons)

    def test_signature_empty_string_is_ineligible(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="new_subfam",
            mechanism_signature="",
            prior_subfamilies_in_family=frozenset(),
            prior_mechanism_signatures_in_family=frozenset(),
        )
        assert eligible is False
        assert any("empty mechanism signature" in r.lower() for r in reasons)


from kryptosbot.family_yield import (
    render_packet,
    render_escape_pressure,
    mechanism_signature_for_theory,
    NON_DSL_INVESTIGATIVE_FAMILIES,
)


class TestMechanismSignature:
    def test_category_a_signature_uses_dsl_spec(self):
        theory_a = {
            "family": "polyalphabetic",
            "subfamily": "vigenere",
            "mechanism": "vig + col",
            "dsl_spec": {"layers": [{"kind": "vigenere", "keyword": "X"}]},
            "anomalies_exploited": [],
            "clue_anchors_used": [],
            "novelty_basis": "totally novel!",
            "minimal_test_spec": {},
        }
        theory_b = dict(theory_a)
        # Same dsl_spec but very different novelty_basis prose.
        theory_b["novelty_basis"] = "different prose"
        sig_a = mechanism_signature_for_theory(theory_a)
        sig_b = mechanism_signature_for_theory(theory_b)
        assert sig_a == sig_b  # novelty_basis must not affect the hash
        assert isinstance(sig_a, str) and len(sig_a) >= 8

    def test_category_a_signature_differs_when_dsl_layers_differ(self):
        theory_a = {
            "family": "polyalphabetic",
            "subfamily": "vigenere",
            "mechanism": "x",
            "dsl_spec": {"layers": [{"kind": "vigenere", "keyword": "X"}]},
            "anomalies_exploited": [],
            "clue_anchors_used": [],
            "novelty_basis": "",
            "minimal_test_spec": {},
        }
        theory_b = dict(theory_a)
        theory_b["dsl_spec"] = {"layers": [{"kind": "beaufort", "keyword": "X"}]}
        assert mechanism_signature_for_theory(theory_a) != mechanism_signature_for_theory(theory_b)

    def test_category_b_signature_uses_structured_fields(self):
        theory = {
            "family": "geometry",
            "subfamily": "spiral",
            "mechanism": "spiral walk on width 21",
            "dsl_spec": None,
            "anomalies_exploited": ["width21_vertical_bigrams"],
            "clue_anchors_used": ["width21"],
            "novelty_basis": "anything",
            "minimal_test_spec": {"method": "spiral_walk"},
        }
        sig = mechanism_signature_for_theory(theory)
        assert isinstance(sig, str) and len(sig) >= 8

    def test_category_b_signature_excludes_novelty_basis(self):
        a = {
            "family": "geometry",
            "subfamily": "spiral",
            "mechanism": "spiral walk on width 21",
            "dsl_spec": None,
            "anomalies_exploited": [],
            "clue_anchors_used": [],
            "novelty_basis": "this is novel because reasons",
            "minimal_test_spec": {"method": "x"},
        }
        b = dict(a)
        b["novelty_basis"] = "completely different prose"
        assert mechanism_signature_for_theory(a) == mechanism_signature_for_theory(b)

    def test_category_b_membership_is_explicit(self):
        # Spec §4.4: NON_DSL_INVESTIGATIVE_FAMILIES is a frozenset we
        # control. physical_overlay must be added deliberately; do not
        # auto-route every novel-mechanism theory.
        assert "geometry" in NON_DSL_INVESTIGATIVE_FAMILIES
        assert "k2_coords" in NON_DSL_INVESTIGATIVE_FAMILIES
        assert "archive_evidence" in NON_DSL_INVESTIGATIVE_FAMILIES

    def test_category_a_signature_normalizes_subfamily_case(self):
        a = {
            "family": "polyalphabetic", "subfamily": "Vigenere",
            "mechanism": "v", "dsl_spec": {"layers": [{"kind": "vigenere"}]},
            "anomalies_exploited": [], "clue_anchors_used": [],
            "novelty_basis": "", "minimal_test_spec": {},
        }
        b = dict(a)
        b["subfamily"] = "  VIGENERE  "
        assert mechanism_signature_for_theory(a) == mechanism_signature_for_theory(b)


class TestRenderPacket:
    def _verdict(self, family, status, trials=100, mean=0.5, best=0.0, promo=0):
        s = FamilyYieldStats(family, trials, mean, best, promo, 0)
        return FamilyYieldVerdict(
            family=family, status=status, reasons=(), stats=s,
        )

    def test_empty_index_returns_no_pressure_marker(self):
        out = render_packet({})
        assert "no family yield data" in out.lower()

    def test_groups_by_status(self):
        idx = {
            "encoding": self._verdict("encoding", "empirically_dead", 826, 0.78, 7.0),
            "grille":   self._verdict("grille",   "low_yield",       162, 0.64, 24.0),
            "novel":    self._verdict("novel",    "insufficient_data", 7, 0.0, 0.0),
            "fractionation": self._verdict("fractionation", "healthy", 100, 5.0, 18.0, promo=1),
        }
        out = render_packet(idx)
        assert "EMPIRICALLY DEAD" in out
        assert "LOW YIELD" in out
        assert "encoding" in out
        assert "grille" in out
        # n, mean, best, promotions must all surface for at least one family
        assert "826" in out
        assert "0.78" in out

    def test_deterministic_ordering(self):
        idx = {
            "z_family": self._verdict("z_family", "empirically_dead", 100, 0.5),
            "a_family": self._verdict("a_family", "empirically_dead", 100, 0.5),
        }
        a = render_packet(idx)
        b = render_packet(idx)
        assert a == b


class TestRenderEscapePressure:
    def test_no_pressure_when_streak_zero(self):
        out = render_escape_pressure(
            streak=0,
            last_status="none",
            blocked=[],
            blocked_total=0,
        )
        assert out.strip() == ""

    def test_streak_one(self):
        out = render_escape_pressure(
            streak=1,
            last_status="needed_but_unavailable",
            blocked=["encoding", "key_tape"],
            blocked_total=2,
        )
        assert "PRIOR CYCLE NEEDED ESCAPE" in out
        assert "2 families blocked" in out

    def test_streak_two_escalates(self):
        out = render_escape_pressure(
            streak=2,
            last_status="needed_but_unavailable",
            blocked=["encoding"],
            blocked_total=1,
        )
        assert "SECOND CONSECUTIVE ESCAPE-NEEDED CYCLE" in out
        assert "1 families blocked" in out

    def test_streak_three_escalates(self):
        out = render_escape_pressure(
            streak=3,
            last_status="needed_but_unavailable",
            blocked=["encoding"],
            blocked_total=1,
        )
        assert "REPEATED ESCAPE FAILURE" in out

    def test_truncation_note_visible(self):
        out = render_escape_pressure(
            streak=1,
            last_status="needed_but_unavailable",
            blocked=["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"],
            blocked_total=17,
        )
        assert "17 families blocked" in out
        assert "showing top 10" in out.lower()

    def test_inconsistent_blocked_total_is_clipped(self):
        # Defensive guard: if a caller passes more blocked items than the
        # claimed total, the function must clip rather than emit a
        # contradiction like "3 families blocked: a, b, c, d, e".
        out = render_escape_pressure(
            streak=1,
            last_status="needed_but_unavailable",
            blocked=["a", "b", "c", "d", "e"],
            blocked_total=3,
        )
        assert "3 families blocked" in out
        # The output should not list 'd' or 'e' since the guard clipped them.
        # Check that only the first 3 families are in the join.
        assert "a, b, c" in out
        assert ", d," not in out
        assert ", e" not in out
