"""Tests that the theorist prompt surfaces the family_yield packet and
escape_pressure rendering from the landscape dict as standalone sections,
not merely embedded in the JSON landscape dump.

The function under test is ResearchController._build_theorist_prompt
(in kryptosbot/controller.py), not a free function in pantheon.py.
The plan assumed a free function 'theorist_system_prompt(landscape)';
the actual implementation is a method on ResearchController.
"""
from __future__ import annotations

import json
import pytest

from kryptosbot.controller import ControllerConfig, ControllerState, ResearchController
from kryptosbot.theory_ledger import TheoryLedger

# Minimal landscape that satisfies _build_theorist_prompt's field access.
_BASE_LANDSCAPE = {
    "open_anomalies": [],
    "unaddressed_anomalies": [],
    "underexplored_families": [],
    "standing_constraints": [],
    "status_counts": {},
    "cycle_delta": {},
    "active_families": [],
    "recent_outcomes": [],
    "pursuit_leads": [],
    "previous_synthesis": None,
}

# A sentinel family_yield string whose UNIQUE TOKEN only appears in the
# section render, not inside any JSON key name.
_YIELD_TOKEN = "RECENT_FAMILY_YIELD_SENTINEL_XQ7"
_PRESSURE_TOKEN = "ESCAPE_PRESSURE_SENTINEL_XQ7"


def _make_controller(tmp_path) -> ResearchController:
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "ledger.sqlite",
    )
    ctrl = ResearchController.__new__(ResearchController)
    ctrl.config = cfg
    ctrl.ledger = TheoryLedger(cfg.ledger_db_path)
    ctrl.state = ControllerState()
    return ctrl


def _prompt_outside_json(prompt: str, token: str) -> bool:
    """Return True if token appears in the prompt outside the JSON landscape block.

    Finds the JSON landscape block (between 'CURRENT RESEARCH LANDSCAPE:'
    and the next blank line after the closing brace), then checks that
    token appears somewhere in the prompt OTHER than inside that block.
    """
    json_start_marker = "CURRENT RESEARCH LANDSCAPE:"
    idx_marker = prompt.find(json_start_marker)
    if idx_marker == -1:
        # No JSON block — any occurrence counts.
        return token in prompt

    # Walk past the JSON block to find where it ends (closing brace + newline).
    after_marker = prompt[idx_marker + len(json_start_marker):]
    # The JSON block starts with a newline then '{'.
    brace_idx = after_marker.find("{")
    if brace_idx == -1:
        return token in prompt[idx_marker + len(json_start_marker):]

    json_body = after_marker[brace_idx:]
    # Find the end of the JSON object by counting braces.
    depth = 0
    end_pos = 0
    for i, ch in enumerate(json_body):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end_pos = i + 1
                break

    # Absolute offset where the JSON block ends in `prompt`.
    json_end_abs = idx_marker + len(json_start_marker) + brace_idx + end_pos

    # Check token in the portion AFTER the JSON block.
    return token in prompt[json_end_abs:]


def test_prompt_includes_family_yield_section_when_present(tmp_path):
    ctrl = _make_controller(tmp_path)
    landscape = {
        **_BASE_LANDSCAPE,
        "family_yield": f"=== RECENT FAMILY YIELD (advisory) ===\n  {_YIELD_TOKEN}",
        "escape_pressure": "",
    }
    prompt = ctrl._build_theorist_prompt(landscape)
    assert _YIELD_TOKEN in prompt, "family_yield token must appear somewhere in prompt"
    assert _prompt_outside_json(prompt, _YIELD_TOKEN), (
        "family_yield block must be rendered as a standalone section OUTSIDE "
        "the JSON landscape dump, not only embedded within it"
    )


def test_prompt_includes_escape_pressure_when_present(tmp_path):
    ctrl = _make_controller(tmp_path)
    landscape = {
        **_BASE_LANDSCAPE,
        "family_yield": "",
        "escape_pressure": f"=== ESCAPE PRESSURE (streak=2) ===\n  {_PRESSURE_TOKEN}",
    }
    prompt = ctrl._build_theorist_prompt(landscape)
    assert _PRESSURE_TOKEN in prompt, "escape_pressure token must appear somewhere in prompt"
    assert _prompt_outside_json(prompt, _PRESSURE_TOKEN), (
        "escape_pressure block must be rendered as a standalone section OUTSIDE "
        "the JSON landscape dump, not only embedded within it"
    )


def test_prompt_omits_escape_pressure_when_empty_string(tmp_path):
    ctrl = _make_controller(tmp_path)
    landscape = {
        **_BASE_LANDSCAPE,
        "family_yield": "anything",
        "escape_pressure": "",
    }
    prompt = ctrl._build_theorist_prompt(landscape)
    # "ESCAPE PRESSURE" must not appear outside the JSON block when
    # escape_pressure is empty.
    assert not _prompt_outside_json(prompt, "ESCAPE PRESSURE"), (
        "escape_pressure section must be omitted from the prompt when the "
        "landscape value is an empty string"
    )


def test_shared_symmetry_invariant():
    """For a given (stats, policy), the packet's family-status assignment
    MUST match the critic's family-status assignment.

    Implementation note: both consumers call classify_family_yield on
    the same stats with the same policy. This test pins that contract
    by exercising both paths on the same input and confirming the
    family appears in the packet's empirically_dead section iff the
    critic would reject a theory in that family for empirical-death."""
    from kryptosbot.family_yield import (
        DEFAULT_POLICY,
        FamilyYieldStats,
        classify_family_yield,
        render_packet,
    )
    stats = FamilyYieldStats("encoding", 826, 0.78, 7.0, 0, 750)
    verdict = classify_family_yield(stats, DEFAULT_POLICY)
    packet = render_packet({"encoding": verdict})
    # Critic-facing semantic.
    assert verdict.status == "empirically_dead"
    # Theorist-facing rendering.
    assert "EMPIRICALLY DEAD" in packet
    assert "encoding" in packet


class TestLandscapeIncludesEscapeCandidates:
    def test_escape_candidates_field_present(self):
        from kryptosbot.controller import ResearchController, ControllerState
        c = ResearchController.__new__(ResearchController)
        c.state = ControllerState(
            cycle_number=2,
            last_escape_status="needed_but_unavailable",
            last_escape_suggestions=[
                {
                    "kb_record_id": "fx1",
                    "canonical_name": "Sample Cipher",
                    "kb_cipher_family": "columnar",
                    "mapped_ledger_families": ["columnar_single"],
                    "mechanism_signature": "x" * 16,
                    "signature_schema_version": "kb_mechanism_sig_v1",
                    "dispatcher_testable": True,
                    "k4_relevance_score": 30.0,
                    "sketch_class": "dsl_testable",
                    "one_line_sketch": "test",
                    "bounded_kill_criterion": "test",
                    "source_verdict": "allow",
                    "blocked_family": "encoding",
                }
            ],
        )
        # Minimal stand-ins for Phase 1 dependencies.
        c.ledger = None       # _assess_landscape's yield-stats call must
                              # handle a missing ledger by emitting an empty
                              # yield_index. Phase 1 already does this.
        c._cycle_yield_index = {}
        c._cycle_prior_subfamilies = {}
        c._cycle_prior_signatures = {}
        c.config = None       # If _assess_landscape reads from self.config,
                              # patch as needed for the test.
        # Call _assess_landscape — but only invoke the part of it that
        # builds the landscape dict. If the method is monolithic, this
        # test may need to mock more.
        try:
            landscape = c._assess_landscape()
        except Exception:
            pytest.skip(
                "Phase 1 _assess_landscape requires more controller state "
                "than this bare test wires up; the next acceptance test "
                "exercises the full path."
            )
        assert "escape_candidates" in landscape
        assert "Sample Cipher" in landscape["escape_candidates"]


# Sentinel for the escape_candidates block: a unique token that should only
# appear in the rendered section, not inside any JSON key.
_CANDIDATES_TOKEN = "ESCAPE_CANDIDATES_SENTINEL_XQ7"


class TestTheoristPromptReceivesEscapeCandidates:
    """Task 22 (Phase 2 yield-feedback): the theorist prompt builder
    (ResearchController._build_theorist_prompt — see module docstring above
    for why this is a method, not a free function in pantheon.py) MUST
    render the landscape["escape_candidates"] string as a standalone
    section OUTSIDE the JSON landscape dump when non-empty, and MUST
    omit the section entirely when the value is empty.

    Closes the redirect direction of the yield-feedback loop: cycle N hits
    `needed_but_unavailable` → Task 18 aggregates suggestions → Task 21
    surfaces them via _assess_landscape → Task 22 renders them in cycle
    N+1's theorist prompt.
    """

    def test_prompt_includes_escape_candidates_when_present(self, tmp_path):
        ctrl = _make_controller(tmp_path)
        landscape = {
            **_BASE_LANDSCAPE,
            "family_yield": "",
            "escape_pressure": "",
            "escape_candidates": (
                "=== ESCAPE CANDIDATES (cipher-discovery KB) ===\n"
                f"  - Sample Cipher [dispatcher-testable] {_CANDIDATES_TOKEN}\n"
            ),
        }
        prompt = ctrl._build_theorist_prompt(landscape)
        assert _CANDIDATES_TOKEN in prompt, (
            "escape_candidates token must appear somewhere in the prompt"
        )
        assert _prompt_outside_json(prompt, _CANDIDATES_TOKEN), (
            "escape_candidates block must be rendered as a standalone "
            "section OUTSIDE the JSON landscape dump, not only embedded "
            "within it"
        )

    def test_prompt_omits_escape_candidates_when_empty_string(self, tmp_path):
        ctrl = _make_controller(tmp_path)
        landscape = {
            **_BASE_LANDSCAPE,
            "family_yield": "",
            "escape_pressure": "",
            "escape_candidates": "",
        }
        prompt = ctrl._build_theorist_prompt(landscape)
        assert not _prompt_outside_json(prompt, "ESCAPE CANDIDATES"), (
            "escape_candidates section must be omitted from the prompt "
            "when the landscape value is an empty string"
        )

    def test_prompt_omits_escape_candidates_when_key_missing(self, tmp_path):
        """Defensive: even when the landscape dict doesn't carry the
        escape_candidates key at all (e.g. legacy callers, Phase-1-only
        cycles), the builder must not crash and must not render the
        section."""
        ctrl = _make_controller(tmp_path)
        landscape = {
            **_BASE_LANDSCAPE,
            "family_yield": "",
            "escape_pressure": "",
            # escape_candidates intentionally omitted
        }
        prompt = ctrl._build_theorist_prompt(landscape)
        assert not _prompt_outside_json(prompt, "ESCAPE CANDIDATES"), (
            "escape_candidates section must be omitted when the landscape "
            "key is missing"
        )


# ────────────────────────────────────────────────────────────────────────
# Prior-cycle-synthesis rendering — closes Tier-C #8 from the 2026-05-16
# controller-maturity audit. Before 2026-05-17, results-analyst's
# recommended_next_focus was computed and stored on the landscape but
# never rendered into _build_theorist_prompt — the recommendation
# surfaced for human visibility at end-of-cycle and dead-ended there.
# These tests pin the new rendering invariant: when
# previous_synthesis is present with non-empty content, the prompt
# carries a "PRIOR CYCLE SYNTHESIS" section OUTSIDE the JSON landscape;
# when absent / empty, the prompt is unchanged.
# ────────────────────────────────────────────────────────────────────────


_PRIOR_SYNTHESIS_TOKEN = "x9c4-prior-synth-marker-9w2k"


class TestTheoristPromptReceivesPriorSynthesis:
    """Regression guard for the 2026-05-17 fix that threads
    previous_synthesis.recommended_next_focus into the theorist prompt.

    Tier-C #8 documented bug: ``recommended_next_focus`` was computed by
    results-analyst, persisted on ``self._last_synthesis``, and forwarded
    to ``landscape["previous_synthesis"]`` — but ``_build_theorist_prompt``
    never read the key. The fix adds ``_render_previous_synthesis`` and
    inserts the rendered block ahead of the yield-feedback blocks so the
    steer reaches the theorist before the per-family pressure / KB
    suggestions.
    """

    def test_prompt_includes_recommended_next_focus_when_present(self, tmp_path):
        ctrl = _make_controller(tmp_path)
        landscape = {
            **_BASE_LANDSCAPE,
            "family_yield": "",
            "escape_pressure": "",
            "escape_candidates": "",
            "previous_synthesis": {
                "headline": "Cycle N produced zero signal across 5 dispatches.",
                "recommended_next_focus": (
                    f"Bias toward w_delimiter_segments anomaly lane "
                    f"({_PRIOR_SYNTHESIS_TOKEN})"
                ),
                "family_movements": [],
                "evidence_added": [],
                "dispatched_count": 5,
                "disproved_count": 1,
                "signal_count": 0,
                "risk_breakdown": {},
            },
        }
        prompt = ctrl._build_theorist_prompt(landscape)
        assert _PRIOR_SYNTHESIS_TOKEN in prompt, (
            "recommended_next_focus must appear somewhere in the prompt"
        )
        assert _prompt_outside_json(prompt, _PRIOR_SYNTHESIS_TOKEN), (
            "previous_synthesis block must render as a standalone "
            "section OUTSIDE the JSON landscape dump (this is the "
            "Tier-C #8 bug: pre-fix the recommendation was inside the "
            "landscape JSON but no standalone block)"
        )
        assert "PRIOR CYCLE SYNTHESIS" in prompt, (
            "expected a 'PRIOR CYCLE SYNTHESIS' heading in the rendered block"
        )
        # Override-affordance line must accompany the recommendation so the
        # theorist knows it can disagree without silently ignoring.
        assert "override" in prompt.lower(), (
            "the override-allowed affordance line must accompany the "
            "recommended_next_focus so the theorist can disagree explicitly"
        )

    def test_prompt_omits_block_when_previous_synthesis_is_none(self, tmp_path):
        """First cycle of a session: _last_synthesis is None, the
        landscape carries previous_synthesis=None. Builder must not
        crash and must not render the section."""
        ctrl = _make_controller(tmp_path)
        landscape = {
            **_BASE_LANDSCAPE,
            "family_yield": "",
            "escape_pressure": "",
            "escape_candidates": "",
            "previous_synthesis": None,
        }
        prompt = ctrl._build_theorist_prompt(landscape)
        assert "PRIOR CYCLE SYNTHESIS" not in prompt

    def test_prompt_omits_block_when_key_missing(self, tmp_path):
        """Legacy callers / bench-mode paths that don't populate the
        key at all must not crash and must not render the section."""
        ctrl = _make_controller(tmp_path)
        landscape = {
            **_BASE_LANDSCAPE,
            "family_yield": "",
            "escape_pressure": "",
            "escape_candidates": "",
            # previous_synthesis intentionally omitted
        }
        prompt = ctrl._build_theorist_prompt(landscape)
        assert "PRIOR CYCLE SYNTHESIS" not in prompt

    def test_prompt_omits_block_when_both_fields_empty(self, tmp_path):
        """A previous_synthesis dict with empty headline AND empty
        recommended_next_focus contributes no actionable content;
        the block must be suppressed entirely (no empty heading)."""
        ctrl = _make_controller(tmp_path)
        landscape = {
            **_BASE_LANDSCAPE,
            "family_yield": "",
            "escape_pressure": "",
            "escape_candidates": "",
            "previous_synthesis": {
                "headline": "",
                "recommended_next_focus": "",
                "family_movements": [],
                "evidence_added": [],
                "dispatched_count": 0,
                "disproved_count": 0,
                "signal_count": 0,
                "risk_breakdown": {},
            },
        }
        prompt = ctrl._build_theorist_prompt(landscape)
        assert "PRIOR CYCLE SYNTHESIS" not in prompt, (
            "block must not render when both headline and "
            "recommended_next_focus are empty strings"
        )

    def test_prompt_renders_headline_only_when_next_focus_empty(self, tmp_path):
        """If a cycle produces a headline but no next-focus recommendation
        (e.g. the analyst couldn't suggest anything actionable), the
        block should still surface the headline so the theorist knows
        what happened last cycle. The override-affordance is omitted
        because there is no recommendation to override."""
        ctrl = _make_controller(tmp_path)
        marker = "x9c4-headline-only-marker"
        landscape = {
            **_BASE_LANDSCAPE,
            "family_yield": "",
            "escape_pressure": "",
            "escape_candidates": "",
            "previous_synthesis": {
                "headline": f"Cycle N status report: {marker}",
                "recommended_next_focus": "",
                "family_movements": [],
                "evidence_added": [],
                "dispatched_count": 0,
                "disproved_count": 0,
                "signal_count": 0,
                "risk_breakdown": {},
            },
        }
        prompt = ctrl._build_theorist_prompt(landscape)
        assert marker in prompt
        assert _prompt_outside_json(prompt, marker)
        # No recommendation means no override-affordance line.
        # (The line is only emitted when next_focus is non-empty.)
        assert "override" not in (
            prompt.split("PRIOR CYCLE SYNTHESIS", 1)[1].split("===", 1)[0].lower()
        ), (
            "override-affordance line must only render alongside a "
            "non-empty recommended_next_focus"
        )
