"""Round-trip tests for Phase 2 KB-suggestion serialization."""
from __future__ import annotations

import json

import pytest

from kryptosbot.kb_injection import (
    KB_SIGNATURE_SCHEMA_VERSION,
    CipherDiscoverySuggestion,
)
from kryptosbot.models import (
    CriticDecision,
    CriticVerdict,
    EmpiricalDeathRejectionPayload,
)


def _example_suggestion(**overrides):
    base = dict(
        kb_record_id="rec-1",
        canonical_name="Sample",
        kb_cipher_family="columnar",
        mapped_ledger_families=("columnar_single",),
        mechanism_signature="aaaaaaaaaaaaaaaa",
        signature_schema_version=KB_SIGNATURE_SCHEMA_VERSION,
        dispatcher_testable=True,
        k4_relevance_score=11.5,
        sketch_class="dsl_testable",
        one_line_sketch="A short sketch.",
        bounded_kill_criterion="Stop if score < 18 across the bounded set.",
        source_verdict="allow",
    )
    base.update(overrides)
    return CipherDiscoverySuggestion(**base)


class TestPayloadRoundTripWithSuggestions:
    def test_payload_to_dict_serializes_suggestions(self):
        payload = EmpiricalDeathRejectionPayload(
            family="encoding",
            verdict=None,
            bypass_failed_reasons=("subfamily seen",),
            suggested_mechanism_records=(_example_suggestion(),),
            suggestion_source="cipher_discovery_kb",
            suggestion_query_scope={"blocked_family": "encoding"},
        )
        d = payload.to_dict()
        assert isinstance(d, dict)
        recs = d.get("suggested_mechanism_records")
        assert isinstance(recs, list)
        assert len(recs) == 1
        assert recs[0]["canonical_name"] == "Sample"
        # JSON serializable end-to-end.
        json.dumps(d)

    def test_payload_round_trip_through_json(self):
        payload = EmpiricalDeathRejectionPayload(
            family="encoding",
            verdict=None,
            bypass_failed_reasons=("x",),
            suggested_mechanism_records=(_example_suggestion(),),
            suggestion_source="cipher_discovery_kb",
            suggestion_query_scope={},
        )
        d = payload.to_dict()
        blob = json.dumps(d)
        reloaded = json.loads(blob)
        payload2 = EmpiricalDeathRejectionPayload.from_dict(reloaded)
        assert payload2.family == "encoding"
        assert len(payload2.suggested_mechanism_records) == 1
        assert payload2.suggested_mechanism_records[0].canonical_name == "Sample"

    def test_critic_verdict_round_trip_with_suggestions(self):
        cv = CriticVerdict(
            decision=CriticDecision.REJECT_EMPIRICALLY_DEAD,
            confidence=0.9,
            reasons=["family dead"],
            empirical_death=EmpiricalDeathRejectionPayload(
                family="encoding",
                verdict=None,
                bypass_failed_reasons=("x",),
                suggested_mechanism_records=(_example_suggestion(),),
                suggestion_source="cipher_discovery_kb",
                suggestion_query_scope={},
            ),
        )
        d = cv.to_dict()
        blob = json.dumps(d)
        cv2 = CriticVerdict.from_dict(json.loads(blob))
        assert cv2.decision == CriticDecision.REJECT_EMPIRICALLY_DEAD
        assert cv2.empirical_death is not None
        assert cv2.empirical_death.suggested_mechanism_records[0].canonical_name == "Sample"

    def test_from_dict_tolerates_legacy_suggested_mechanisms_key(self):
        """Pre-Phase-2 ledger rows used `suggested_mechanisms: tuple[str,...]`
        which Phase 1 always emitted empty. from_dict must treat the old
        name as either an empty record list or, if non-empty strings are
        present, ignore them rather than crash."""
        legacy = {
            "family": "encoding",
            "verdict": {},
            "bypass_failed_reasons": [],
            "suggested_mechanisms": [],
            "suggestion_source": "none",
            "suggestion_query_scope": {},
        }
        payload = EmpiricalDeathRejectionPayload.from_dict(legacy)
        assert payload.family == "encoding"
        assert payload.suggested_mechanism_records == ()
        assert payload.suggestion_source == "none"

    def test_suggestion_query_scope_round_trips(self):
        payload = EmpiricalDeathRejectionPayload(
            family="encoding",
            verdict=None,
            bypass_failed_reasons=(),
            suggested_mechanism_records=(),
            suggestion_source="none",
            suggestion_query_scope={"blocked_family": "encoding", "max_per_call": 12},
        )
        payload2 = EmpiricalDeathRejectionPayload.from_dict(payload.to_dict())
        assert payload2.suggestion_query_scope == {"blocked_family": "encoding", "max_per_call": 12}
