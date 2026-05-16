"""Tests for new CriticDecision variant + EmpiricalDeathRejectionPayload + CriticVerdict field."""
from __future__ import annotations

from kryptosbot.models import CriticDecision, CriticVerdict


def test_critic_decision_has_reject_empirically_dead():
    assert CriticDecision.REJECT_EMPIRICALLY_DEAD.value == "reject_empirically_dead"


def test_empirical_death_payload_dataclass_shape():
    from kryptosbot.models import EmpiricalDeathRejectionPayload
    from kryptosbot.family_yield import FamilyYieldStats, FamilyYieldVerdict

    stats = FamilyYieldStats("encoding", 826, 0.78, 7.0, 0, 750)
    verdict = FamilyYieldVerdict("encoding", "empirically_dead", (), stats)
    payload = EmpiricalDeathRejectionPayload(
        family="encoding",
        verdict=verdict,
        bypass_failed_reasons=("subfamily already represented",),
    )
    assert payload.suggested_mechanisms == ()  # Phase-1 default
    assert payload.family == "encoding"


def test_critic_verdict_empirical_death_defaults_none():
    v = CriticVerdict(decision=CriticDecision.APPROVE)
    assert v.empirical_death is None


def test_critic_verdict_round_trip_with_empirical_death_none():
    v = CriticVerdict(decision=CriticDecision.APPROVE)
    d = v.to_dict()
    restored = CriticVerdict.from_dict(d)
    assert restored.decision == CriticDecision.APPROVE
    assert restored.empirical_death is None


def test_critic_verdict_round_trip_with_empirical_death_populated():
    from kryptosbot.models import EmpiricalDeathRejectionPayload
    from kryptosbot.family_yield import FamilyYieldStats, FamilyYieldVerdict
    stats = FamilyYieldStats("encoding", 826, 0.78, 7.0, 0, 750)
    verdict = FamilyYieldVerdict("encoding", "empirically_dead", ("r",), stats)
    payload = EmpiricalDeathRejectionPayload(
        family="encoding",
        verdict=verdict,
        bypass_failed_reasons=("r1",),
    )
    v = CriticVerdict(
        decision=CriticDecision.REJECT_EMPIRICALLY_DEAD,
        confidence=0.9,
        reasons=["dead"],
        empirical_death=payload,
    )
    d = v.to_dict()
    restored = CriticVerdict.from_dict(d)
    assert restored.decision == CriticDecision.REJECT_EMPIRICALLY_DEAD
    assert restored.empirical_death is not None
    assert restored.empirical_death.family == "encoding"
    assert restored.empirical_death.bypass_failed_reasons == ("r1",)


def test_pre_phase_1_critic_verdict_json_loads_cleanly():
    """A pre-Phase-1 JSON blob lacks the empirical_death key; loading
    must succeed with empirical_death=None."""
    legacy_dict = {
        "decision": "reject_duplicate",
        "confidence": 1.0,
        "reasons": ["same as hid_001"],
        "similar_hypotheses": ["hid_001"],
        "contradicting_facts": [],
        "estimated_information_gain": "",
        "reviewed_at": "2026-04-01T00:00:00Z",
    }
    v = CriticVerdict.from_dict(legacy_dict)
    assert v.decision == CriticDecision.REJECT_DUPLICATE
    assert v.empirical_death is None
