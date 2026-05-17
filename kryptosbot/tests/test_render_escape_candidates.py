"""Tests for the next-cycle KB-escape-candidates prompt renderer."""
from __future__ import annotations

import pytest


def _example_suggestion_dict(canonical_name, family, *, kfa_score=42.0, dispatcher_testable=True, sketch_class="dsl_testable", sig=None):
    return {
        "kb_record_id": f"rec-{canonical_name}",
        "canonical_name": canonical_name,
        "kb_cipher_family": "columnar",
        "mapped_ledger_families": ["columnar_single"],
        "mechanism_signature": (sig or canonical_name.lower())[:16].ljust(16, "x"),
        "signature_schema_version": "kb_mechanism_sig_v1",
        "dispatcher_testable": dispatcher_testable,
        "k4_relevance_score": kfa_score,
        "sketch_class": sketch_class,
        "one_line_sketch": "A short sketch.",
        "bounded_kill_criterion": "Stop if no run scores >= 18.",
        "source_verdict": "allow",
        "blocked_family": family,
    }


class TestRenderEscapeCandidates:
    def _renderer(self):
        from kryptosbot.controller import ResearchController
        c = ResearchController.__new__(ResearchController)
        return c._render_escape_candidates

    def test_none_status_emits_no_block(self):
        out = self._renderer()(
            status="none",
            suggestions=[_example_suggestion_dict("Alpha", "encoding")],
        )
        assert out == ""

    def test_no_candidates_status_emits_no_block(self):
        out = self._renderer()(
            status="no_candidates",
            suggestions=[_example_suggestion_dict("Alpha", "encoding")],
        )
        assert out == ""

    def test_needed_and_satisfied_status_emits_no_block(self):
        out = self._renderer()(
            status="needed_and_satisfied",
            suggestions=[_example_suggestion_dict("Alpha", "encoding")],
        )
        assert out == ""

    def test_needed_but_unavailable_caps_at_8_total(self):
        # 12 suggestions across 4 families: must clamp to 8 total.
        suggestions = [
            _example_suggestion_dict(f"Cipher{i}", f"fam{i % 4}", kfa_score=50 - i)
            for i in range(12)
        ]
        out = self._renderer()(
            status="needed_but_unavailable",
            suggestions=suggestions,
        )
        assert out
        # Count rendered canonical_name occurrences.
        rendered_names = [s for s in suggestions if s["canonical_name"] in out]
        assert len(rendered_names) <= 8

    def test_needed_but_unavailable_caps_at_3_per_family(self):
        # 5 suggestions all in encoding: must clamp to 3 of them.
        suggestions = [
            _example_suggestion_dict(f"Cipher{i}", "encoding", kfa_score=50 - i)
            for i in range(5)
        ]
        out = self._renderer()(
            status="needed_but_unavailable",
            suggestions=suggestions,
        )
        rendered_names = [s for s in suggestions if s["canonical_name"] in out]
        assert len(rendered_names) == 3

    def test_partial_empirical_block_caps_at_3_total(self):
        suggestions = [
            _example_suggestion_dict(f"Cipher{i}", f"fam{i}", kfa_score=50 - i)
            for i in range(10)
        ]
        out = self._renderer()(
            status="partial_empirical_block",
            suggestions=suggestions,
        )
        rendered_names = [s for s in suggestions if s["canonical_name"] in out]
        assert len(rendered_names) <= 3
        # Framed as advisory (the word should appear).
        assert "advisory" in out.lower()

    def test_unknown_status_emits_nothing(self):
        out = self._renderer()(
            status="some_future_status",
            suggestions=[_example_suggestion_dict("Alpha", "encoding")],
        )
        assert out == ""

    def test_empty_suggestions_emits_nothing(self):
        for status in ("needed_but_unavailable", "partial_empirical_block"):
            out = self._renderer()(status=status, suggestions=[])
            assert out == ""
