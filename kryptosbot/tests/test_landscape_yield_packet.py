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
