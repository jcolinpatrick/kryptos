"""R3-3 theorist-prompt integrity test.

Verifies the DSL_SPEC CONTRACT section is correctly embedded in the
theorist prompt. A static-analysis guard against prompt drift:
catches the failure mode where a future edit removes the example
block or the supported-kinds list, which would tank the live spec-
production rate silently.

This test complements (not replaces) the real-theorist --dry-run
measurement documented in the R3-3 phase report. Both are required:
this test proves the prompt is structurally correct; the dry-run
proves the structure actually induces valid spec output from real
theorists.
"""
from __future__ import annotations

import pytest

import inspect

from kryptosbot.controller import ResearchController


def _get_prompt(tmp_path=None) -> str:
    """Extract the theorist prompt template as source text.

    Avoids running _assess_landscape (which needs heavy controller
    state to execute) and _build_theorist_prompt (which pulls config
    fields that change). Inspecting the source directly is sufficient
    to verify the prompt contract's literal contents — the precise
    strings the theorist reads.
    """
    return inspect.getsource(ResearchController._build_theorist_prompt)


def test_theorist_prompt_includes_dsl_spec_contract(tmp_path):
    prompt = _get_prompt(tmp_path)
    assert "DSL_SPEC CONTRACT" in prompt, (
        "theorist prompt must declare the DSL_SPEC CONTRACT section "
        "so theorists understand the requirement"
    )


def test_theorist_prompt_lists_supported_kinds(tmp_path):
    prompt = _get_prompt(tmp_path)
    # All 9 kinds must appear somewhere in the prompt's supported list.
    for kind in ("identity", "vigenere", "beaufort", "variant_beaufort",
                 "columnar", "atbash", "procedural", "grille", "polybius"):
        assert kind in prompt, (
            f"theorist prompt missing supported kind {kind!r}; "
            "DSL coverage won't be accurately conveyed"
        )


def test_theorist_prompt_lists_untranslatable_kinds(tmp_path):
    prompt = _get_prompt(tmp_path)
    # After B-DSL-expanded (2026-04-22), only ``key_tape`` remains
    # deferred. The other four (rail_fence, route, myszkowski,
    # quagmire) got first-class dispatcher translators and no longer
    # belong on the untranslatable list. A future brief may add
    # key_tape or other families — update this test to match.
    for kind in ("key_tape",):
        assert kind in prompt, (
            f"theorist prompt should flag {kind!r} as untranslatable"
        )
    # Guard against regression: families that B-DSL-expanded moved into
    # _SUPPORTED_KINDS must NOT appear in the theorist's
    # untranslatable-kinds listing (a specific line in DSL_SPEC_CONTRACT).
    import re
    untranslatable_line = re.search(
        r"Untranslatable kinds.*?:\s*\n\s*([^\n]+)", prompt, re.DOTALL,
    )
    assert untranslatable_line, (
        "theorist prompt must declare an 'Untranslatable kinds' line"
    )
    for kind in ("rail_fence", "route", "myszkowski", "quagmire"):
        assert kind not in untranslatable_line.group(1), (
            f"{kind!r} is now supported and must not appear on the "
            f"untranslatable-kinds listing"
        )


def test_theorist_prompt_enumerates_dsl_enum_domains(tmp_path):
    prompt = _get_prompt(tmp_path)
    for token in (
        "direct_positional",
        "post_transposition",
        "free",
        "crib_only",
        "crib_plus_bean",
        "ngram_vs_null",
        "composite",
        "random_text",
        "shuffled_ct",
        "matched_variant_family",
        "monte_carlo_cached",
        "AZ",
        "KA",
        "keyword_mixed",
    ):
        assert token in prompt, (
            f"theorist prompt must enumerate DSL token {token!r} "
            "to reduce enum invention drift"
        )


def test_theorist_prompt_calls_out_invalid_free_search_alias(tmp_path):
    prompt = _get_prompt(tmp_path)
    assert "free_search" in prompt
    assert 'only free-alignment enum value is "free"' in prompt


def test_theorist_prompt_includes_three_worked_examples(tmp_path):
    prompt = _get_prompt(tmp_path)
    # The three examples have distinct headers. Verify all three appear.
    for header in ("Example A", "Example B", "Example C"):
        assert header in prompt, (
            f"theorist prompt must include {header} from DSL_CUTOVER_CONTRACT §1.3"
        )


def test_theorist_prompt_names_non_dsl_families(tmp_path):
    prompt = _get_prompt(tmp_path)
    # NON_DSL_FAMILIES members must appear verbatim so theorists know
    # which families are exempt from the Category-A requirement.
    for family in ("geometry", "k2_coords", "geodetic", "antipodes",
                   "archive_evidence", "crib_analysis", "k3_continuity"):
        assert family in prompt, (
            f"theorist prompt must list NON_DSL_FAMILIES member {family!r} "
            "so theorists know Category B doesn't need a spec"
        )


def test_theorist_prompt_discourages_fabrication(tmp_path):
    """Brief §1 principle: theorists must not fabricate specs to
    satisfy the DSL requirement. The prompt's language must include
    an explicit discourage-fabrication clause."""
    prompt = _get_prompt(tmp_path)
    # The prompt says: "DO NOT fabricate one. Set dsl_spec=null and
    # accept rejection"
    assert "DO NOT fabricate" in prompt or "not fabricate" in prompt, (
        "theorist prompt must explicitly discourage spec fabrication; "
        "this is the scope-discipline clause"
    )
