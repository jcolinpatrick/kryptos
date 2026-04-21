from kryptosbot.api_client import (
    K4_SYSTEM_PROMPT,
    _PROMPT_PERIODIC_POLY,
    _PROMPT_PURE_TRANSPOSITION,
)


def test_k4_system_prompt_avoids_unscoped_proof_language():
    assert "## What Is MATHEMATICALLY PROVEN" not in K4_SYSTEM_PROMPT
    assert "proves outermost layer is SUBSTITUTION" not in K4_SYSTEM_PROMPT
    assert "Treat every item below as scoped" in K4_SYSTEM_PROMPT
    assert "NOT a proof" in K4_SYSTEM_PROMPT
    assert "that the outermost layer must be substitution" in K4_SYSTEM_PROMPT


def test_k4_system_prompt_marks_eliminations_as_scoped():
    assert "conditionally eliminated" in K4_SYSTEM_PROMPT
    assert "This is not a global elimination" in K4_SYSTEM_PROMPT


def test_hypothesis_format_rules_avoid_globalized_elimination_language():
    from kryptosbot.api_client import HYPOTHESIS_FORMAT

    assert "DO NOT treat any project elimination as global" in HYPOTHESIS_FORMAT
    assert "conditionally eliminated in-project" in HYPOTHESIS_FORMAT
    assert "universally impossible" in HYPOTHESIS_FORMAT


def test_prompt_uses_registry_backed_elimination_rendering():
    assert _PROMPT_PERIODIC_POLY in K4_SYSTEM_PROMPT
    assert _PROMPT_PURE_TRANSPOSITION in K4_SYSTEM_PROMPT
    assert "Elimination scope" in _PROMPT_PERIODIC_POLY
