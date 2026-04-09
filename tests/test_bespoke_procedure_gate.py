"""Tests for the bespoke-cipher procedure gate in novelty triage.

Covers:
    - Hypothesis dataclass carries bespoke + procedure_id fields
    - Default bespoke=False: hypotheses proceed through normal triage
    - bespoke=True + licensed procedure_id: hypothesis proceeds
    - bespoke=True + missing procedure_id: eliminated with certificate
    - bespoke=True + unlicensed procedure_id: eliminated with certificate
    - Gate runs before transform_stack validation (order matters)
    - Rejection certificate is a well-formed PROCEDURE_POLICY_VIOLATION
"""
from __future__ import annotations

import json

import pytest

from kryptos.admissibility import (
    EliminationReason,
    certificate_from_json,
)
from kryptos.novelty.hypothesis import (
    Hypothesis,
    HypothesisStatus,
    ResearchQuestion,
)
from kryptos.novelty.triage import (
    _gate_bespoke_procedure,
    triage_hypothesis,
)


# ── Dataclass carries the new fields ────────────────────────────────────

class TestHypothesisSchemaExtensions:

    def test_default_bespoke_is_false(self):
        h = Hypothesis(description="test")
        assert h.bespoke is False
        assert h.procedure_id is None

    def test_bespoke_can_be_set(self):
        h = Hypothesis(
            description="test",
            bespoke=True,
            procedure_id="abscissa_as_keyword",
        )
        assert h.bespoke is True
        assert h.procedure_id == "abscissa_as_keyword"

    def test_from_dict_roundtrip_preserves_bespoke(self):
        h = Hypothesis(
            description="roundtrip",
            bespoke=True,
            procedure_id="quagmire_iii_family",
        )
        d = h.to_dict()
        # Strip derived fields before reconstruction
        d.pop("priority_score", None)
        h2 = Hypothesis.from_dict(d)
        assert h2.bespoke is True
        assert h2.procedure_id == "quagmire_iii_family"


# ── Gate: bespoke=False passes through ──────────────────────────────────

class TestGateBypass:

    def test_non_bespoke_returns_none(self):
        h = Hypothesis(description="standard cipher test")
        assert _gate_bespoke_procedure(h) is None
        # Caller should see an unchanged hypothesis object
        assert h.status is HypothesisStatus.PROPOSED

    def test_triage_hypothesis_still_runs_normal_path_for_non_bespoke(self):
        # An empty-stack non-bespoke hypothesis hits the existing
        # "No transform stack defined" elimination, not the gate.
        h = Hypothesis(description="empty")
        result = triage_hypothesis(h)
        assert result.status is HypothesisStatus.ELIMINATED
        assert "transform stack" in result.triage_detail.lower()
        # No procedure certificate on this elimination reason.
        assert result.elimination_reason == ""


# ── Gate: bespoke=True + licensed procedure_id ──────────────────────────

class TestGateAcceptLicensed:

    def test_licensed_procedure_returns_none(self):
        # None from the gate means "proceed to normal triage"
        h = Hypothesis(
            description="quagmire III test",
            bespoke=True,
            procedure_id="quagmire_iii_family",
        )
        assert _gate_bespoke_procedure(h) is None

    def test_licensed_bespoke_hypothesis_flows_to_normal_triage(self):
        # Bespoke but licensed: the gate accepts, and normal triage
        # takes over. With an empty stack the normal triage ends in
        # the "No transform stack defined" elimination, which is
        # expected: the gate does not fabricate a stack for the
        # caller.
        h = Hypothesis(
            description="licensed but no stack",
            bespoke=True,
            procedure_id="abscissa_as_keyword",
        )
        result = triage_hypothesis(h)
        assert result.status is HypothesisStatus.ELIMINATED
        assert "transform stack" in result.triage_detail.lower()
        # Crucially: the elimination reason is NOT a procedure policy
        # violation; the gate passed cleanly.
        assert result.elimination_reason == ""


# ── Gate: bespoke=True + missing procedure_id ───────────────────────────

class TestGateRejectMissing:

    def test_missing_procedure_id_eliminates(self):
        h = Hypothesis(
            description="bespoke without id",
            bespoke=True,
            procedure_id=None,
        )
        result = _gate_bespoke_procedure(h)
        assert result is not None
        assert result.status is HypothesisStatus.ELIMINATED
        assert result.triage_score == 0.0

    def test_missing_procedure_id_certificate_shape(self):
        h = Hypothesis(
            description="missing id",
            bespoke=True,
        )
        result = _gate_bespoke_procedure(h)
        assert result.elimination_reason
        cert = certificate_from_json(result.elimination_reason)
        assert cert is not None
        assert cert.reason is EliminationReason.PROCEDURE_POLICY_VIOLATION
        assert "procedure_id" in cert.summary.lower()
        assert cert.evidence["procedure_id"] is None
        assert cert.evidence["bespoke"] is True

    def test_empty_string_procedure_id_is_treated_as_missing(self):
        h = Hypothesis(
            description="empty id",
            bespoke=True,
            procedure_id="",  # falsy
        )
        result = _gate_bespoke_procedure(h)
        assert result is not None
        assert result.status is HypothesisStatus.ELIMINATED


# ── Gate: bespoke=True + unlicensed procedure_id ────────────────────────

class TestGateRejectUnlicensed:

    def test_unlicensed_procedure_eliminates(self):
        h = Hypothesis(
            description="bespoke with unlicensed id",
            bespoke=True,
            procedure_id="fictitious_cipher_xyz",
        )
        result = _gate_bespoke_procedure(h)
        assert result is not None
        assert result.status is HypothesisStatus.ELIMINATED

    def test_unlicensed_procedure_certificate_shape(self):
        h = Hypothesis(
            description="unlicensed",
            bespoke=True,
            procedure_id="not_a_real_procedure",
        )
        result = _gate_bespoke_procedure(h)
        cert = certificate_from_json(result.elimination_reason)
        assert cert is not None
        assert cert.reason is EliminationReason.PROCEDURE_POLICY_VIOLATION
        assert cert.evidence["procedure_id"] == "not_a_real_procedure"
        assert "allowlist" in cert.summary.lower()


# ── Gate ordering: runs before transform_stack check ────────────────────

class TestGateOrdering:
    """The gate must run before transform_stack validation so that a
    malformed or empty bespoke hypothesis is eliminated with a
    PROCEDURE_POLICY_VIOLATION certificate (the informative reason)
    rather than a generic 'no transform stack' message (which would
    obscure the actual fault)."""

    def test_bespoke_unlicensed_with_empty_stack_gets_procedure_cert(self):
        h = Hypothesis(
            description="unlicensed + empty stack",
            bespoke=True,
            procedure_id="fictitious_xyz",
            transform_stack=[],  # also invalid, but gate should fire first
        )
        result = triage_hypothesis(h)
        assert result.status is HypothesisStatus.ELIMINATED
        cert = certificate_from_json(result.elimination_reason)
        assert cert is not None
        assert cert.reason is EliminationReason.PROCEDURE_POLICY_VIOLATION

    def test_bespoke_missing_id_with_empty_stack_gets_procedure_cert(self):
        h = Hypothesis(
            description="missing id + empty stack",
            bespoke=True,
            procedure_id=None,
            transform_stack=[],
        )
        result = triage_hypothesis(h)
        assert result.status is HypothesisStatus.ELIMINATED
        cert = certificate_from_json(result.elimination_reason)
        assert cert is not None
        assert cert.reason is EliminationReason.PROCEDURE_POLICY_VIOLATION


# ── Backwards compatibility ─────────────────────────────────────────────

class TestBackwardsCompatibility:
    """The new fields default to bespoke=False / procedure_id=None,
    so all pre-existing generators and tests continue to work without
    modification. These tests lock in that invariant."""

    def test_old_hypothesis_dict_without_bespoke_round_trips(self):
        # Simulate a serialised hypothesis from before the schema
        # extension; the new fields should fill in from defaults.
        old_dict = {
            "description": "legacy hypothesis",
            "transform_stack": [],
            "research_questions": ["RQ-1"],
            "status": "proposed",
        }
        h = Hypothesis.from_dict(old_dict)
        assert h.bespoke is False
        assert h.procedure_id is None

    def test_triage_hypothesis_non_bespoke_unchanged_flow(self):
        # An existing generator pattern: non-bespoke, simple key in
        # transform stack. Should route to triage_simple_key without
        # the gate interfering. (We don't actually run triage_simple_key
        # here — we just verify the gate doesn't short-circuit.)
        h = Hypothesis(
            description="standard test",
            transform_stack=[{"type": "vigenere", "params": {"key": "FOO"}}],
        )
        gate_result = _gate_bespoke_procedure(h)
        assert gate_result is None  # gate passes through
